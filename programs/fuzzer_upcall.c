/*
 * Copyright (C) 2017-2018 Felix Weinrank
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include "usrsctp.h"

#define MAX_PACKET_SIZE (1 << 16)
#define FILENAME_BUFFER 512

#define FUZZ_FAST
//#define FUZZ_INTERLEAVING
//#define FUZZ_EXPLICIT_EOR
#define FUZZ_STREAM_RESET
#define FUZZ_DISABLE_LINGER
//#define FUZZ_VERBOSE

static int fd_udp_client, fd_udp_server;
static struct socket *socket_client, *socket_server_listening;
static uint8_t sockets_open = 0;
static pthread_t tid_c, tid_s;

static char *common_header_client[12];
static char *common_header_server[12];

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

#define CS_CLIENT            1
#define CS_SERVER_LISTENING  2
#define CS_SERVER_CONNECTED  3

#define CS_STATE_OPEN        1
#define CS_STATE_CLOSED      2


struct connection_status {
	uint8_t type;
	uint8_t state;
	char *data;
	size_t data_size;
};


#if defined(FUZZ_VERBOSE)
#define printf_fuzzer(...) { \
	printf("[%5d][%15.15s] ", __LINE__, __func__); \
	printf(__VA_ARGS__); \
	printf("\n"); \
}

#define printf_fuzzer_raw(...) { \
	printf(__VA_ARGS__); \
}
#else // !defined(FUZZING_MODE) || defined(FUZZ_VERBOSE)
#define printf_fuzzer(format, ...)
#define printf_fuzzer_raw(format, ...)
#endif //!defined(FUZZING_MODE) || defined(FUZZ_VERBOSE)


static int
handle_association_change_event(struct sctp_assoc_change *sac)
{
	unsigned int i, n;
	int retval = 0;

	printf_fuzzer("handling event");

	printf_fuzzer_raw("Association change : ");
	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			printf_fuzzer_raw("SCTP_COMM_UP");
			break;
		case SCTP_COMM_LOST:
			printf_fuzzer_raw("SCTP_COMM_LOST");
			break;
		case SCTP_RESTART:
			printf_fuzzer_raw("SCTP_RESTART");
			break;
		case SCTP_SHUTDOWN_COMP:
			printf_fuzzer_raw("SCTP_SHUTDOWN_COMP");
			break;
		case SCTP_CANT_STR_ASSOC:
			printf_fuzzer_raw("SCTP_CANT_STR_ASSOC");
			break;
		default:
			printf_fuzzer_raw("UNKNOWN");
			break;
	}
	printf_fuzzer_raw(", streams (in/out) = (%u/%u)", sac->sac_inbound_streams, sac->sac_outbound_streams);
	n = sac->sac_length - sizeof(struct sctp_assoc_change);
	if (((sac->sac_state == SCTP_COMM_UP) ||
	     (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
		printf_fuzzer_raw(", supports");
		for (i = 0; i < n; i++) {
			switch (sac->sac_info[i]) {
			case SCTP_ASSOC_SUPPORTS_PR:
				printf_fuzzer_raw(" PR");
				break;
			case SCTP_ASSOC_SUPPORTS_AUTH:
				printf_fuzzer_raw(" AUTH");
				break;
			case SCTP_ASSOC_SUPPORTS_ASCONF:
				printf_fuzzer_raw(" ASCONF");
				break;
			case SCTP_ASSOC_SUPPORTS_MULTIBUF:
				printf_fuzzer_raw(" MULTIBUF");
				break;
			case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
				printf_fuzzer_raw(" RE-CONFIG");
				break;
			default:
				printf_fuzzer_raw(" UNKNOWN(0x%02x)", sac->sac_info[i]);
				break;
			}
		}
	} else if (((sac->sac_state == SCTP_COMM_LOST) || (sac->sac_state == SCTP_CANT_STR_ASSOC)) && (n > 0)) {
		printf_fuzzer_raw(", ABORT =");
		for (i = 0; i < n; i++) {
			printf_fuzzer_raw(" 0x%02x", sac->sac_info[i]);
		}
	}
	printf_fuzzer_raw(".\n");
	if ((sac->sac_state == SCTP_CANT_STR_ASSOC) || (sac->sac_state == SCTP_SHUTDOWN_COMP) || (sac->sac_state == SCTP_COMM_LOST)) {
		retval = -1;
	}
	return(retval);
}

static int
handle_notification(union sctp_notification *notif, size_t n)
{
	int retval = 0;
	if (notif->sn_header.sn_length != (uint32_t)n) {
		return(retval);
	}

	switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			printf_fuzzer("SCTP_ASSOC_CHANGE");
			retval = handle_association_change_event(&(notif->sn_assoc_change));
			break;
		case SCTP_PEER_ADDR_CHANGE:
			printf_fuzzer("SCTP_PEER_ADDR_CHANGE");
			//handle_peer_address_change_event(&(notif->sn_paddr_change));
			break;
		case SCTP_REMOTE_ERROR:
			printf_fuzzer("SCTP_REMOTE_ERROR");
			break;
		case SCTP_SHUTDOWN_EVENT:
			printf_fuzzer("SCTP_SHUTDOWN_EVENT");
			break;
		case SCTP_ADAPTATION_INDICATION:
			printf_fuzzer("SCTP_ADAPTATION_INDICATION");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			printf_fuzzer("SCTP_PARTIAL_DELIVERY_EVENT");
			break;
		case SCTP_AUTHENTICATION_EVENT:
			printf_fuzzer("SCTP_AUTHENTICATION_EVENT");
			break;
		case SCTP_SENDER_DRY_EVENT:
			printf_fuzzer("SCTP_SENDER_DRY_EVENT");
			break;
		case SCTP_NOTIFICATIONS_STOPPED_EVENT:
			printf_fuzzer("SCTP_NOTIFICATIONS_STOPPED_EVENT");
			break;
		case SCTP_SEND_FAILED_EVENT:
			printf_fuzzer("SCTP_SEND_FAILED_EVENT");
			//handle_send_failed_event(&(notif->sn_send_failed_event));
			break;
		case SCTP_STREAM_RESET_EVENT:
			printf_fuzzer("SCTP_STREAM_RESET_EVENT");
			break;
		case SCTP_ASSOC_RESET_EVENT:
			printf_fuzzer("SCTP_ASSOC_RESET_EVENT");
			break;
		case SCTP_STREAM_CHANGE_EVENT:
			printf_fuzzer("SCTP_STREAM_CHANGE_EVENT");
			break;
		default:
			break;
	}

	return(retval);
}

static void
handle_upcall(struct socket *sock, void *arg, int flgs)
{
	int events = usrsctp_get_events(sock);
	struct connection_status *cs = (struct connection_status*) arg;

	if (arg == NULL) {
		printf_fuzzer("error: upcall - arg == NULL");
		exit(EXIT_FAILURE);
	}

	pthread_t tid;
	tid = pthread_self();
	printf_fuzzer("Thread: %u", (uint32_t)tid);

	if (cs->type == CS_SERVER_LISTENING) {
		// upcall for listening socket -> call accept!
		struct socket* conn_sock;
		struct connection_status* cs_new;

		cs_new = (struct connection_status *) calloc(1, sizeof(struct connection_status));
		cs_new->type = CS_SERVER_CONNECTED;

		if (((conn_sock = usrsctp_accept(sock, NULL, NULL)) == NULL) && (errno != EINPROGRESS)) {
			perror("usrsctp_accept");
			exit(EXIT_FAILURE);
		}
		pthread_mutex_lock(&mutex);
		sockets_open++;
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);

		usrsctp_set_upcall(conn_sock, handle_upcall, cs_new);

		// close listening socket, we do not need it anymore
		free(cs);
		usrsctp_close(sock);
		pthread_mutex_lock(&mutex);
		sockets_open--;
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
		return;

	} else if (cs->type == CS_SERVER_CONNECTED || cs->type == CS_CLIENT) {
		// upcall for connected socket -> read/write/whatever
		if (events & SCTP_EVENT_WRITE) {

			if (cs->type == CS_CLIENT && cs->data) {
#if 0
				if (usrsctp_sendv(sock, cs->data, cs->data_size, NULL, 0, NULL, 0, 0, 0) < 0) {
					if (errno != EAGAIN) {
						usrsctp_close(sock);
						printf_fuzzer("client socket %p closed\n", (void *)sock);
						return;
					}
				}
#endif
				// prepare and inject packet
				// take input from fuzzer/commandline and prepend common client header
				// delete packet after injecting


#if defined(FUZZ_EXPLICIT_EOR)
				struct sctp_sndinfo sndinfo;
				memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
				//sndinfo.snd_sid = 1207;
				//sndinfo.snd_flags 	= SCTP_EOR;
				sndinfo.snd_ppid 	= htonl(1207);
				if (usrsctp_sendv(socket_client, &sndinfo, sizeof(struct sctp_sndinfo), NULL, 0, &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
					perror("sctp_sendv socket_client");
					exit(EXIT_FAILURE);
				}
#endif //defined(FUZZ_EXPLICIT_EOR)

				char* pkt = (char *) malloc(cs->data_size + 12);
				memcpy(pkt, common_header_client, 12);
				memcpy(pkt + 12, cs->data, cs->data_size);

				if (send(fd_udp_client, pkt, cs->data_size + 12, 0) < 0) {
					exit(EXIT_FAILURE);
				}
				free(pkt);
				cs->data = NULL;
				cs->data_size = 0;
				free(cs);
				usrsctp_close(sock);
				pthread_mutex_lock(&mutex);
				sockets_open--;
				pthread_cond_signal(&cond);
				pthread_mutex_unlock(&mutex);
				return;
			}
		}

		while (events & SCTP_EVENT_READ) {
			struct sctp_recvv_rn rn;
			ssize_t n;
			struct sockaddr_in addr;
			char *buf = (char*) calloc(1, MAX_PACKET_SIZE);
			int flags = 0;
			socklen_t len = (socklen_t) sizeof(struct sockaddr_in);
			unsigned int infotype = 0;
			socklen_t infolen = sizeof(struct sctp_recvv_rn);
			memset(&rn, 0, sizeof(struct sctp_recvv_rn));
			int notification_retval = 0;

			n = usrsctp_recvv(sock, buf, MAX_PACKET_SIZE, (struct sockaddr *) &addr, &len, (void *)&rn, &infolen, &infotype, &flags);

			printf_fuzzer("usrsctp_recvv() for %p", (void *)sock);

			if (n > 0) {
				if (flags & MSG_NOTIFICATION) {
					notification_retval = handle_notification((union sctp_notification *)buf, n);
				} else {
					if (write(fileno(stdout), buf, n) < 0) {
						perror("write");
						exit(EXIT_FAILURE);
					}
				}
			}

			free(buf);

			if (n == -1 || notification_retval == -1) {
				printf_fuzzer("n : %zd || notification_retval : %d", n, notification_retval);
				free(cs);
				usrsctp_close(sock);
				pthread_mutex_lock(&mutex);
				sockets_open--;
				pthread_cond_signal(&cond);
				pthread_mutex_unlock(&mutex);
				break;
			}

			events = usrsctp_get_events(sock);
		}

		if (events & SCTP_EVENT_ERROR) {
			printf_fuzzer("SCTP_EVENT_ERROR for %p", (void *)sock);
		}
	}
	printf_fuzzer("exit");
	return;
}

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	int *fdp = (int *)addr;

	// we copy the common header of the client/server for building fuzzer packets
	if (*fdp == fd_udp_client) {
		memcpy(common_header_client, buf, 12);
	} else if (*fdp == fd_udp_server) {
		memcpy(common_header_server, buf, 12);
	}

	if (send(*fdp, buf, length, 0) < 0) {
		return (errno);
	} else {
		return (0);
	}
}

static void*
handle_packets(void* arg)
{
	int* fdp;
	ssize_t length;
	char buf[MAX_PACKET_SIZE];

	fdp = (int*)arg;
	for (;;) {
		length = recv(*fdp, buf, MAX_PACKET_SIZE, 0);
		if (length > 0) {
			usrsctp_conninput(fdp, buf, (size_t)length, 0);
		}
	}
	return (NULL);
}

void debug_printf(const char* format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

int init_fuzzer(void)
{
	static uint8_t initialized = 0;
	struct sockaddr_in sin_s, sin_c;
	socklen_t name_len;

#if defined(FUZZ_FAST)
	if (initialized) {
		return 0;
	}
#endif

#if defined(FUZZ_FAST)
	printf_fuzzer("FUZZ_FAST");
#endif

#if defined(FUZZ_INTERLEAVING)
	printf_fuzzer("FUZZ_INTERLEAVING");
#endif

#if defined(FUZZ_EXPLICIT_EOR)
	printf_fuzzer("FUZZ_EXPLICIT_EOR");
#endif

#if defined(FUZZ_STREAM_RESET)
	printf_fuzzer("FUZZ_STREAM_RESET");
#endif

#if defined(FUZZ_DISABLE_LINGER)
	printf_fuzzer("FUZZ_DISABLE_LINGER");
#endif

	usrsctp_init(0, conn_output, NULL);
	usrsctp_enable_crc32c_offload();

	/* set up a connected UDP socket */
	if ((fd_udp_client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket fd_udp_client");
		exit(EXIT_FAILURE);
	}
	if ((fd_udp_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket fd_udp_server");
		exit(EXIT_FAILURE);
	}

	memset(&sin_c, 0, sizeof(struct sockaddr_in));
	sin_c.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin_c.sin_len = sizeof(struct sockaddr_in);
#endif
	sin_c.sin_port = htons(0);
	sin_c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	memset(&sin_s, 0, sizeof(struct sockaddr_in));
	sin_s.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin_s.sin_len = sizeof(struct sockaddr_in);
#endif
	sin_s.sin_port = htons(0);
	sin_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd_udp_client, (struct sockaddr*)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("bind fd_udp_client");
		exit(EXIT_FAILURE);
	}

	if (bind(fd_udp_server, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("bind fd_udp_server");
		exit(EXIT_FAILURE);
	}

	name_len = (socklen_t) sizeof(struct sockaddr_in);
	if (getsockname(fd_udp_client, (struct sockaddr*)&sin_c, &name_len)) {
		perror("getsockname fd_udp_client");
		exit(EXIT_FAILURE);
	}

	name_len = (socklen_t) sizeof(struct sockaddr_in);
	if (getsockname(fd_udp_server, (struct sockaddr*)&sin_s, &name_len)) {
		perror("getsockname fd_udp_server");
		exit(EXIT_FAILURE);
	}

	if (connect(fd_udp_client, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("connect fd_udp_client");
		exit(EXIT_FAILURE);
	}

	if (connect(fd_udp_server, (struct sockaddr*)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("connect fd_udp_server");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&tid_c, NULL, &handle_packets, (void*)&fd_udp_client)) {
		perror("pthread_create tid_c");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&tid_s, NULL, &handle_packets, (void*)&fd_udp_server)) {
		perror("pthread_create tid_s");
		exit(EXIT_FAILURE);
	};

#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

	usrsctp_register_address((void*)&fd_udp_client);
	usrsctp_register_address((void*)&fd_udp_server);

	initialized = 1;

	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
	printf_fuzzer_raw("\n\n\n\n\n");
	printf_fuzzer("Lets go....................");

	struct sockaddr_conn sconn;
	static uint16_t port = 1;
	struct timespec time_to_wait;
	struct timeval tv;
	int timedwait_retval = 0;

#if defined(FUZZ_DISABLE_LINGER)
	struct linger so_linger;
#endif
#if defined(FUZZ_EXPLICIT_EOR) || defined(FUZZ_INTERLEAVING)
	int enable;
#endif
#if defined(FUZZ_STREAM_RESET) || defined(FUZZ_INTERLEAVING)
	struct sctp_assoc_value assoc_val;
#endif
	struct sctp_event event;
	uint16_t event_types[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED_EVENT,
		SCTP_REMOTE_ERROR,
		SCTP_SHUTDOWN_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT
	};
	unsigned long i;
	struct connection_status* cs;

	init_fuzzer();
	port = (port % 32768) + 1;

	if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket - socket_client");
		exit(EXIT_FAILURE);
	}
	sockets_open++;
	usrsctp_set_non_blocking(socket_client, 1);


	if ((socket_server_listening = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket - socket_server_listening");
		exit(EXIT_FAILURE);
	}
	sockets_open++;
	usrsctp_set_non_blocking(socket_server_listening, 1);

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT socket_client");
			exit(EXIT_FAILURE);
		}
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT socket_server_listening");
			exit(EXIT_FAILURE);
		}
	}

#if defined(FUZZ_DISABLE_LINGER)
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	if (usrsctp_setsockopt(socket_client, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) < 0) {
		perror("usrsctp_setsockopt SO_LINGER");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_DISABLE_LINGER)

#if defined(FUZZ_EXPLICIT_EOR)
	enable = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR socket_client");
		exit(EXIT_FAILURE);
	}

	enable = 1;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR socket_server_listening");
		exit(EXIT_FAILURE);
	}
#endif // defined(FUZZ_EXPLICIT_EOR)

#if defined(FUZZ_STREAM_RESET)
	assoc_val.assoc_id = SCTP_ALL_ASSOC;
	assoc_val.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_val, sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET socket_client");
		exit(EXIT_FAILURE);
	}
	/* Allow resetting streams. */
	assoc_val.assoc_id = SCTP_ALL_ASSOC;
	assoc_val.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_val, sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET socket_server_listening");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_STREAM_RESET)


#if defined(FUZZ_INTERLEAVING)

#if !defined(SCTP_INTERLEAVING_SUPPORTED)
#define SCTP_INTERLEAVING_SUPPORTED 0x00001206
#endif // !defined(SCTP_INTERLEAVING_SUPPORTED)

	enable = 2;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &enable, sizeof(enable)) < 0) {
		perror("usrsctp_setsockopt SCTP_FRAGMENT_INTERLEAVE socket_client");
		exit(EXIT_FAILURE);
	}

	memset(&assoc_val, 0, sizeof(assoc_val));
	assoc_val.assoc_value = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_val, sizeof(assoc_val)) < 0) {
		perror("usrsctp_setsockopt SCTP_INTERLEAVING_SUPPORTED socket_client");
		exit(EXIT_FAILURE);
	}

	enable = 2;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &enable, sizeof(enable)) < 0) {
		perror("usrsctp_setsockopt SCTP_FRAGMENT_INTERLEAVE socket_server_listening");
		exit(EXIT_FAILURE);
	}

	memset(&assoc_val, 0, sizeof(assoc_val));
	assoc_val.assoc_value = 1;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_val, sizeof(assoc_val)) < 0) {
		perror("usrsctp_setsockopt SCTP_INTERLEAVING_SUPPORTED socket_server_listening");
		exit(EXIT_FAILURE);
	}
#endif // defined(FUZZ_INTERLEAVING)

	/* Bind the client side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#if defined(HAVE_SCONN_LEN)
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif // defined(HAVE_SCONN_LEN)
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = &fd_udp_client;
	if (usrsctp_bind(socket_client, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind socket_client");
		exit(EXIT_FAILURE);
	}

	/* Bind the server side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#if defined(HAVE_SCONN_LEN)
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif // defined(HAVE_SCONN_LEN)
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = &fd_udp_server;
	if (usrsctp_bind(socket_server_listening, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind socket_server_listening");
		exit(EXIT_FAILURE);
	}

	/* Make server side passive... */
	if (usrsctp_listen(socket_server_listening, 1) < 0) {
		perror("usrsctp_listen socket_server_listening");
		exit(EXIT_FAILURE);
	}

	cs = (struct connection_status *) calloc(1, sizeof(struct connection_status));
	cs->type = CS_SERVER_LISTENING;

#if defined(FUZZ_DISABLE_LINGER)
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	if (usrsctp_setsockopt(socket_server_listening, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) < 0) {
		perror("usrsctp_setsockopt socket_server_listening");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_DISABLE_LINGER)

	usrsctp_set_upcall(socket_server_listening, handle_upcall, cs);

	/* Initiate the handshake */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#if defined(HAVE_SCONN_LEN)
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif // defined(HAVE_SCONN_LEN)
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = &fd_udp_client;

	cs = (struct connection_status *) calloc(1, sizeof(struct connection_status));
	cs->type = CS_CLIENT;
	cs->data = (char *) data;
	cs->data_size = data_size;

	usrsctp_set_upcall(socket_client, handle_upcall, cs);

	if (usrsctp_connect(socket_client, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		if (errno != EINPROGRESS) {
			perror("usrsctp_connect socket_client");
			exit(EXIT_FAILURE);
		}
	}

	gettimeofday(&tv, NULL);
	time_to_wait.tv_sec = tv.tv_sec + 5;
	time_to_wait.tv_nsec = 0;

	pthread_mutex_lock(&mutex);
	while (sockets_open) {
		printf_fuzzer("waiting for sockets %d...", sockets_open);
		timedwait_retval = pthread_cond_timedwait(&cond, &mutex, &time_to_wait);

		if (timedwait_retval == ETIMEDOUT) {
			printf("Tor 3 - der Zonk!\n");
			usrsctp_close(socket_client);
			usrsctp_close(socket_server_listening);
			break;
		}
	}
	pthread_mutex_unlock(&mutex);

#if !defined(FUZZ_FAST)
	//fprintf(stderr, "%s nearly am Ende...\n", __func__);

	usrsctp_deregister_address((void*)&fd_udp_client);
	usrsctp_deregister_address((void*)&fd_udp_server);

	while (usrsctp_finish()) {
		//sleep(1);
		//printf_fuzzer("finishing....");
	}

	pthread_cancel(tid_c);
	pthread_cancel(tid_s);

	pthread_join(tid_c, NULL);
	pthread_join(tid_s, NULL);

	close(fd_udp_client);
	close(fd_udp_server);
#endif // !defined(FUZZ_FAST)

	printf_fuzzer("finished...");

	return (0);
}

#if !defined(FUZZING_MODE)
void test_input_file(char *file_path) {
	char *data;
	size_t data_size;
	FILE *file;

	file = fopen(file_path, "rb");
	if (!file) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	fseek(file, 0, SEEK_END);
	data_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	data = malloc(data_size);
	if (fread(data, 1, data_size, file) != data_size) {
		fprintf(stderr, "fread failed!\n");
		exit(EXIT_FAILURE);
	}
	fclose(file);

	LLVMFuzzerTestOneInput((const uint8_t *)data, data_size);

	free(data);
}

int main(int argc, char *argv[])
{
	struct stat stat_buf;
	DIR *d;
	struct dirent *dp;
	char file_path[FILENAME_BUFFER];


	if (argc != 2) {
		printf("[FILE/DIR] argument missing\n");
		exit(EXIT_FAILURE);
	}

	if (stat(argv[1], &stat_buf)) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	if (stat_buf.st_mode & S_IFDIR) {
		printf("testing directory: %s\n", argv[1]);

		if (!(d = opendir(argv[1]))) {
			perror("opendir");
			exit(EXIT_FAILURE);
		}

		while ((dp = readdir(d)) != NULL) {
			snprintf(file_path, FILENAME_BUFFER, "%s/%s", argv[1], dp->d_name);
			printf("%s \n", file_path);

			if (dp->d_type == DT_DIR) {
				printf("skip!\n");
				continue;
			}

			test_input_file(file_path);
		}

		closedir(d);

		// directory
	} else if (stat_buf.st_mode & S_IFREG) {
		printf("testing file: %s\n", argv[1]);
		test_input_file(argv[1]);
	} else {
		printf("somethig's odd...\n");
		exit(EXIT_FAILURE);
	}

#if defined(FUZZ_FAST)
	usrsctp_deregister_address((void*)&fd_udp_client);
	usrsctp_deregister_address((void*)&fd_udp_server);

	while (usrsctp_finish()) {
		usleep(100 * 1000);
	}

	pthread_cancel(tid_c);
	pthread_cancel(tid_s);

	pthread_join(tid_c, NULL);
	pthread_join(tid_s, NULL);

	close(fd_udp_client);
	close(fd_udp_server);
#endif // !defined(FUZZ_FAST)


	return (0);
}
#endif
