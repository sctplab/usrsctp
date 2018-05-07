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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
extern "C" {
#include "usrsctp.h"
}

#define MAX_PACKET_SIZE (1 << 16)

#define FUZZ_FAST
//#define FUZZ_INTERLEAVING
#define FUZZ_EXPLICIT_EOR
//#define FUZZ_STREAM_RESET
//#define FUZZ_DISABLE_LINGER

static int fd_udp_client, fd_udp_server;
static struct socket *socket_client, *socket_server, *socket_server_listening;
static uint8_t socket_server_open = 0;
static pthread_t tid_c, tid_s;

static char *common_header_client[12];
static char *common_header_server[12];

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

static void
handle_association_change_event(struct sctp_assoc_change *sac)
{
	unsigned int i, n;

	printf("Association change ");
	switch (sac->sac_state) {
	case SCTP_COMM_UP:
		printf("SCTP_COMM_UP");
		break;
	case SCTP_COMM_LOST:
		printf("SCTP_COMM_LOST");
		break;
	case SCTP_RESTART:
		printf("SCTP_RESTART");
		break;
	case SCTP_SHUTDOWN_COMP:
		printf("SCTP_SHUTDOWN_COMP");
		break;
	case SCTP_CANT_STR_ASSOC:
		printf("SCTP_CANT_STR_ASSOC");
		break;
	default:
		printf("UNKNOWN");
		break;
	}
	printf(", streams (in/out) = (%u/%u)",
	       sac->sac_inbound_streams, sac->sac_outbound_streams);
	n = sac->sac_length - sizeof(struct sctp_assoc_change);
	if (((sac->sac_state == SCTP_COMM_UP) ||
	     (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
		printf(", supports");
		for (i = 0; i < n; i++) {
			switch (sac->sac_info[i]) {
			case SCTP_ASSOC_SUPPORTS_PR:
				printf(" PR");
				break;
			case SCTP_ASSOC_SUPPORTS_AUTH:
				printf(" AUTH");
				break;
			case SCTP_ASSOC_SUPPORTS_ASCONF:
				printf(" ASCONF");
				break;
			case SCTP_ASSOC_SUPPORTS_MULTIBUF:
				printf(" MULTIBUF");
				break;
			case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
				printf(" RE-CONFIG");
				break;
			default:
				printf(" UNKNOWN(0x%02x)", sac->sac_info[i]);
				break;
			}
		}
	} else if (((sac->sac_state == SCTP_COMM_LOST) ||
	            (sac->sac_state == SCTP_CANT_STR_ASSOC)) && (n > 0)) {
		printf(", ABORT =");
		for (i = 0; i < n; i++) {
			printf(" 0x%02x", sac->sac_info[i]);
		}
	}
	printf(".\n");
	if ((sac->sac_state == SCTP_CANT_STR_ASSOC) ||
	    (sac->sac_state == SCTP_SHUTDOWN_COMP) ||
	    (sac->sac_state == SCTP_COMM_LOST)) {
		exit(0);
	}
	return;
}

static void
handle_notification(union sctp_notification *notif, size_t n)
{
	if (notif->sn_header.sn_length != (uint32_t)n) {
		return;
	}
	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		printf("SCTP_ASSOC_CHANGE\n");
		handle_association_change_event(&(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		printf("SCTP_PEER_ADDR_CHANGE\n");
		//handle_peer_address_change_event(&(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		printf("SCTP_REMOTE_ERROR\n");
		break;
	case SCTP_SHUTDOWN_EVENT:
		printf("SCTP_SHUTDOWN_EVENT\n");
		break;
	case SCTP_ADAPTATION_INDICATION:
		printf("SCTP_ADAPTATION_INDICATION\n");
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
		printf("SCTP_PARTIAL_DELIVERY_EVENT\n");
		break;
	case SCTP_AUTHENTICATION_EVENT:
		printf("SCTP_AUTHENTICATION_EVENT\n");
		break;
	case SCTP_SENDER_DRY_EVENT:
		printf("SCTP_SENDER_DRY_EVENT\n");
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
		printf("SCTP_NOTIFICATIONS_STOPPED_EVENT\n");
		break;
	case SCTP_SEND_FAILED_EVENT:
		printf("SCTP_SEND_FAILED_EVENT\n");
		//handle_send_failed_event(&(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		printf("SCTP_STREAM_RESET_EVENT\n");
		break;
	case SCTP_ASSOC_RESET_EVENT:
		printf("SCTP_ASSOC_RESET_EVENT\n");
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		printf("SCTP_STREAM_CHANGE_EVENT\n");
		break;
	default:
		break;
	}
}

static int
receive_cb(struct socket* sock, union sctp_sockstore addr, void* data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void* ulp_info)
{
	printf("\n\nMessage %p received on sock = %p.\n\n\n", data, (void*)sock);
	if (data) {
		if (flags & MSG_NOTIFICATION) {
			handle_notification((union sctp_notification *)data, datalen);
		} else if ((flags & MSG_NOTIFICATION) == 0) {
			printf("Messsage of length %d received via %p:%u on stream %d with SSN %u and TSN %u, PPID %u, context %u, flags %x.\n",
				(int)datalen,
				addr.sconn.sconn_addr,
				ntohs(addr.sconn.sconn_port),
				rcv.rcv_sid,
				rcv.rcv_ssn,
				rcv.rcv_tsn,
				ntohl(rcv.rcv_ppid),
				rcv.rcv_context,
				flags);
		}
		free(data);
	} else {
		//usrsctp_deregister_address(ulp_info);
		usrsctp_close(sock);
		if (sock == socket_server) {
			printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> usrsctp server socket closed...\n");
			socket_server_open = 0;
		} else if (sock == socket_client) {
			printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> usrsctp client socket closed...\n");
		}
	}
	return (1);
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
	printf("FUZZ_FAST\n");
#endif

#if defined(FUZZ_INTERLEAVING)
	printf("FUZZ_INTERLEAVING\n");
#endif

#if defined(FUZZ_EXPLICIT_EOR)
	printf("FUZZ_EXPLICIT_EOR\n");
#endif

#if defined(FUZZ_STREAM_RESET)
	printf("FUZZ_STREAM_RESET\n");
#endif

#if defined(FUZZ_DISABLE_LINGER)
	printf("FUZZ_DISABLE_LINGER\n");
#endif

	usrsctp_init(0, conn_output, debug_printf);
	usrsctp_enable_crc32c_offload();

	/* set up a connected UDP socket */
	if ((fd_udp_client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if ((fd_udp_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
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
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (bind(fd_udp_server, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	name_len = (socklen_t) sizeof(struct sockaddr_in);
	if (getsockname(fd_udp_client, (struct sockaddr*)&sin_c, &name_len)) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}

	name_len = (socklen_t) sizeof(struct sockaddr_in);
	if (getsockname(fd_udp_server, (struct sockaddr*)&sin_s, &name_len)) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}

	if (connect(fd_udp_client, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	if (connect(fd_udp_server, (struct sockaddr*)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
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

#if defined(FUZZING_MODE)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
#else // defined(FUZZING_MODE)
int main(int argc, char *argv[])
{
	char *data_sample = "SCTPSCTPSCTPSCTPSCTPSCTPSCTP!!!!";
	char *data = data_sample;
	size_t data_size = strlen(data);
	FILE *file;

	if (argc > 1) {
		file = fopen(argv[1], "rb");

		if (!file) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}

		fseek(file, 0, SEEK_END);
		data_size = ftell(file);
		fseek(file, 0, SEEK_SET);
		data = (char*)malloc(data_size);
		fread(data, data_size, 1, file);
		fclose(file);
	}
#endif // defined(FUZZING_MODE)

	struct sockaddr_conn sconn;
	static uint16_t port = 1;
	struct linger so_linger;
	int enable;
	char *pkt;
	struct sctp_assoc_value assoc_val;
	struct sctp_event event;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE, SCTP_PEER_ADDR_CHANGE, SCTP_SEND_FAILED_EVENT};
	unsigned long i;

	init_fuzzer();
	port = (port % 32768) + 1;

	if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, &fd_udp_client)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}

	if ((socket_server_listening = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, &fd_udp_server)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT");
		}
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(socket_server, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT");
		}
	}

#if defined(FUZZ_DISABLE_LINGER)
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	if (usrsctp_setsockopt(socket_client, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) < 0) {
		perror("usrsctp_setsockopt 1");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_DISABLE_LINGER)

#if defined(FUZZ_EXPLICIT_EOR)
	enable = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR");
		exit(EXIT_FAILURE);
	}

	enable = 1;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR");
		exit(EXIT_FAILURE);
	}
#endif // defined(FUZZ_EXPLICIT_EOR)

#if defined(FUZZ_STREAM_RESET)
	assoc_val.assoc_id = SCTP_ALL_ASSOC;
	assoc_val.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_val, sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET");
		exit(EXIT_FAILURE);
	}
	/* Allow resetting streams. */
	assoc_val.assoc_id = SCTP_ALL_ASSOC;
	assoc_val.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_val, sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_STREAM_RESET)


#if defined(FUZZ_INTERLEAVING)

#if !defined(SCTP_INTERLEAVING_SUPPORTED)
#define SCTP_INTERLEAVING_SUPPORTED 0x00001206
#endif // !defined(SCTP_INTERLEAVING_SUPPORTED)

	enable = 2;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &enable, sizeof(enable)) < 0) {
		perror("usrsctp_setsockopt 1");
		exit(EXIT_FAILURE);
	}

	memset(&assoc_val, 0, sizeof(assoc_val));
	assoc_val.assoc_value = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_val, sizeof(assoc_val)) < 0) {
		perror("usrsctp_setsockopt 2");
		exit(EXIT_FAILURE);
	}

	enable = 2;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &enable, sizeof(enable)) < 0) {
		perror("usrsctp_setsockopt 3");
		exit(EXIT_FAILURE);
	}

	assoc_val.assoc_value = 1;
	if (usrsctp_setsockopt(socket_server_listening, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_val, sizeof(assoc_val)) < 0) {
		perror("usrsctp_setsockopt 4");
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
		perror("usrsctp_bind 1");
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
		perror("usrsctp_bind 2");
		exit(EXIT_FAILURE);
	}

	/* Make server side passive... */
	if (usrsctp_listen(socket_server_listening, 1) < 0) {
		perror("usrsctp_listen");
		exit(EXIT_FAILURE);
	}

	/* Initiate the handshake */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#if defined(HAVE_SCONN_LEN)
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif // defined(HAVE_SCONN_LEN)
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = &fd_udp_client;

	if (usrsctp_connect(socket_client, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_connect");
		exit(EXIT_FAILURE);
	}

	if ((socket_server = usrsctp_accept(socket_server_listening, NULL, NULL)) == NULL) {
		perror("usrsctp_accept");
		exit(EXIT_FAILURE);
	}

	socket_server_open = 1;

#if defined(FUZZ_DISABLE_LINGER)
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	if (usrsctp_setsockopt(socket_server, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) < 0) {
		perror("usrsctp_setsockopt 3");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_DISABLE_LINGER)

	// close listening socket
	usrsctp_close(socket_server_listening);

#if defined(FUZZ_EXPLICIT_EOR)
	struct sctp_sndinfo sndinfo;
	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	//sndinfo.snd_sid = 1207;
	//sndinfo.snd_flags 	= SCTP_EOR;
	sndinfo.snd_ppid 	= htonl(1207);
	if (usrsctp_sendv(socket_client, &sndinfo, sizeof(struct sctp_sndinfo), NULL, 0, &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("sctp_sendv");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_EXPLICIT_EOR)

	// prepare and inject packet
	// take input from fuzzer/commandline and prepend common client header
	// delete packet after injecting
	pkt = (char *) malloc(data_size + 12);
	memcpy(pkt, common_header_client, 12);
	memcpy(pkt + 12, data, data_size);
	usrsctp_conninput(&fd_udp_server, pkt, data_size + 12, 0);
	free(pkt);

#if !defined(FUZZING_MODE)
	// we have read a file, free allocated memory
	if (data != data_sample) {
		free(data);
	}
#endif // !defined(FUZZING_MODE)

	// we close the client side, server side is closed upon reading zero
	usrsctp_close(socket_client);
	//usrsctp_close(socket_server);

#if !defined(FUZZ_FAST) || !defined(FUZZING_MODE)
	while (socket_server_open) {
		sleep(1);
		printf("waiting for server close...\n");
	}

	usrsctp_deregister_address((void*)&fd_udp_client);
	usrsctp_deregister_address((void*)&fd_udp_server);

	while (usrsctp_finish()) {
		sleep(1);
		printf("finishing....\n");
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
