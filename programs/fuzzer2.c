/*
 * Copyright (C) 2011-2013 Michael Tuexen
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
#include <usrsctp.h>

//#define FUZZ_FAST 1
#define MAX_PACKET_SIZE (1 << 16)
#define LINE_LENGTH (1 << 20)
#define DISCARD_PPID 39

static int fd_c, fd_s;
static struct socket *s_c, *s_s, *s_l;
static pthread_t tid_c, tid_s;
static char *s_cheader[12];
static char *c_cheader[12];

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	char *dump_buf;
	int *fdp;

	fdp = (int *)addr;

	if (*fdp == fd_c) {
		memcpy(c_cheader, buf, 12);
	}

	if (*fdp == fd_s) {
		memcpy(s_cheader, buf, 12);
	}

	//fprintf(stderr, "%s - %d - %d - %d\n", __func__, fd_c, fd_s, *fdp);

	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		//fprintf(stderr, "%s", dump_buf);
		usrsctp_freedumpbuffer(dump_buf);
	}
	if (send(*fdp, buf, length, 0) < 0) {
		return (errno);
	} else {
		return (0);
	}
}

static int
receive_cb(struct socket* sock, union sctp_sockstore addr, void* data,
	size_t datalen, struct sctp_rcvinfo rcv, int flags, void* ulp_info)
{
	//printf("Message %p received on sock = %p.\n", data, (void*)sock);
	if (data) {
		if ((flags & MSG_NOTIFICATION) == 0 && 0) {
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
	}
	else {
		usrsctp_deregister_address(ulp_info);
		usrsctp_close(sock);
	}
	return (1);
}

static void*
handle_packets(void* arg)
{
	int* fdp;
	char* dump_buf;
	ssize_t length;
	char buf[MAX_PACKET_SIZE];

	fdp = (int*)arg;
	for (;;) {
#if defined(__NetBSD__)
		pthread_testcancel();
#endif
		length = recv(*fdp, buf, MAX_PACKET_SIZE, 0);
		if (length > 0) {
			if ((dump_buf = usrsctp_dumppacket(buf, (size_t)length, SCTP_DUMP_INBOUND)) != NULL) {
				//fprintf(stderr, "%s", dump_buf);
				usrsctp_freedumpbuffer(dump_buf);
			}
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

#if defined(FUZZ_FAST)
	if (initialized) {
		return 0;
	}
#endif

	struct sockaddr_in sin_s, sin_c;
	struct sockaddr_conn sconn;
	int cur_buf_size, snd_buf_size, rcv_buf_size;
	socklen_t opt_len;

	usrsctp_init(0, conn_output, debug_printf);
	usrsctp_enable_crc32c_offload();
	/* set up a connected UDP socket */
	if ((fd_c = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if ((fd_s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	memset(&sin_c, 0, sizeof(struct sockaddr_in));
	sin_c.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin_c.sin_len = sizeof(struct sockaddr_in);
#endif
	sin_c.sin_port = htons(9900);
	sin_c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	memset(&sin_s, 0, sizeof(struct sockaddr_in));
	sin_s.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin_s.sin_len = sizeof(struct sockaddr_in);
#endif
	sin_s.sin_port = htons(9901);
	sin_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd_c, (struct sockaddr*)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (bind(fd_s, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (connect(fd_c, (struct sockaddr*)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	if (connect(fd_s, (struct sockaddr*)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	if (pthread_create(&tid_c, NULL, &handle_packets, (void*)&fd_c)) {
		perror("pthread_create tid_c");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&tid_s, NULL, &handle_packets, (void*)&fd_s)) {
		perror("pthread_create tid_s");
		exit(EXIT_FAILURE);
	};
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	usrsctp_sysctl_set_sctp_ecn_enable(0);
	usrsctp_register_address((void*)&fd_c);
	usrsctp_register_address((void*)&fd_s);
	if ((s_c = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, &fd_c)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	opt_len = (socklen_t)sizeof(int);
	cur_buf_size = 0;
	if (usrsctp_getsockopt(s_c, SOL_SOCKET, SO_SNDBUF, &cur_buf_size, &opt_len) < 0) {
		perror("usrsctp_getsockopt");
		exit(EXIT_FAILURE);
	}
	//printf("Change send socket buffer size from %d ", cur_buf_size);
	snd_buf_size = 1 << 20; /* 1 MB */
	if (usrsctp_setsockopt(s_c, SOL_SOCKET, SO_SNDBUF, &snd_buf_size, sizeof(int)) < 0) {
		perror("usrsctp_setsockopt");
		exit(EXIT_FAILURE);
	}
	opt_len = (socklen_t)sizeof(int);
	cur_buf_size = 0;
	if (usrsctp_getsockopt(s_c, SOL_SOCKET, SO_SNDBUF, &cur_buf_size, &opt_len) < 0) {
		perror("usrsctp_getsockopt");
		exit(EXIT_FAILURE);
	}
	//printf("to %d.\n", cur_buf_size);
	if ((s_l = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, &fd_s)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	opt_len = (socklen_t)sizeof(int);
	cur_buf_size = 0;
	if (usrsctp_getsockopt(s_l, SOL_SOCKET, SO_RCVBUF, &cur_buf_size, &opt_len) < 0) {
		perror("usrsctp_getsockopt");
		exit(EXIT_FAILURE);
	}
	//printf("Change receive socket buffer size from %d ", cur_buf_size);
	rcv_buf_size = 1 << 16; /* 64 KB */
	if (usrsctp_setsockopt(s_l, SOL_SOCKET, SO_RCVBUF, &rcv_buf_size, sizeof(int)) < 0) {
		perror("usrsctp_setsockopt");
		exit(EXIT_FAILURE);
	}
	opt_len = (socklen_t)sizeof(int);
	cur_buf_size = 0;
	if (usrsctp_getsockopt(s_l, SOL_SOCKET, SO_RCVBUF, &cur_buf_size, &opt_len) < 0) {
		perror("usrsctp_getsockopt");
		exit(EXIT_FAILURE);
	}
	//printf("to %d.\n", cur_buf_size);
	/* Bind the client side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = &fd_c;
	if (usrsctp_bind(s_c, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
	/* Bind the server side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = &fd_s;
	if (usrsctp_bind(s_l, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
	/* Make server side passive... */
	if (usrsctp_listen(s_l, 1) < 0) {
		perror("usrsctp_listen");
		exit(EXIT_FAILURE);
	}
	/* Initiate the handshake */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = &fd_c;

	if (usrsctp_connect(s_c, (struct sockaddr*)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_connect");
		exit(EXIT_FAILURE);
	}

	if ((s_s = usrsctp_accept(s_l, NULL, NULL)) == NULL) {
		perror("usrsctp_accept");
		exit(EXIT_FAILURE);
	}

	usrsctp_close(s_l);

	initialized = 1;

	return 0;
}

#if defined(FUZZING_MODE)
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
#else // defined(FUZZING_MODE)
int main(void)
{
	char data[] = "SCTPSCTPSCTPSCTPSCTPSCTPSCTP!!!!";
	size_t data_size = strlen(data);
#endif // defined(FUZZING_MODE)

	init_fuzzer();

#if 1
	char *pkt = malloc(data_size + 12);
	memcpy(pkt, c_cheader, 12);
	memcpy(pkt + 12, data, data_size);

	// magic happens here
	usrsctp_conninput(&fd_s, pkt, data_size + 12, 0);

	free(pkt);
#elif

	usrsctp_conninput(&fd_s, data, data_size, 0);
#endif

#if !defined(FUZZ_FAST)
	//usrsctp_shutdown(s_c, SHUT_WR);
	usrsctp_close(s_c);

	while (usrsctp_finish() != 0) {
		//sleep(1);
	}
	pthread_cancel(tid_c);
	pthread_join(tid_c, NULL);
	pthread_cancel(tid_s);
	pthread_join(tid_s, NULL);
	if (close(fd_c) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}
	if (close(fd_s) < 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}
#endif //!defined(FUZZ_FAST)

	return (0);
}
