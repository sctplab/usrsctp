/*
 * Copyright (C) 2011-2012 Michael Tuexen
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

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <usrsctp.h>

#define MAX_PACKET_SIZE (1<<16)
#define LINE_LENGTH 80
#define DISCARD_PPID 39

static void *
handle_packets(void *arg)
{
#ifdef _WIN32
	SOCKET *fdp;
#else
	int *fdp;
#endif
	char *buf;
	char *dump_buf;
	ssize_t length;

#ifdef _WIN32
	fdp = (SOCKET *)arg;
#else
	fdp = (int *)arg;
#endif
	if ((buf = (char *)malloc(MAX_PACKET_SIZE)) == NULL) {
		return (NULL);
	}
	for (;;) {
		length = recv(*fdp, buf, MAX_PACKET_SIZE, 0);
		if (length > 0) {
			dump_buf = usrsctp_dumppacket(buf, (size_t)length, SCTP_DUMP_INBOUND);
			printf("%s", dump_buf);
			usrsctp_freedumpbuffer(dump_buf);
			usrsctp_conninput(fdp, buf, (size_t)length, 0);
		}
	}
	free(buf);
	return (NULL);
}

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	char *dump_buf;
#ifdef _WIN32
	SOCKET *fdp;
#else
	int *fdp;
#endif

#ifdef _WIN32
	fdp = (SOCKET *)addr;
#else
	fdp = (int *)addr;
#endif
	dump_buf = usrsctp_dumppacket(buf, (size_t)length, SCTP_DUMP_OUTBOUND);
	printf("%s", dump_buf);
	usrsctp_freedumpbuffer(dump_buf);
#ifdef _WIN32
	if (send(*fdp, buf, length, 0) == SOCKET_ERROR) {
		return (WSAGetLastError());
#else
	if (send(*fdp, buf, length, 0) < 0) {
		return (errno);
#endif
	} else {
		return (0);
	}
}

static int
receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	printf("Message received on sock = %p.\n", (void *)sock);
	if (data) {
		if ((flags & MSG_NOTIFICATION) == 0) {
			printf("Msg of length %d received via %p:%u on stream %d with SSN %u and TSN %u, PPID %d, context %u.\n",
			       (int)datalen,
			       addr.sconn.sconn_addr,
			       ntohs(addr.sconn.sconn_port),
			       rcv.rcv_sid,
			       rcv.rcv_ssn,
			       rcv.rcv_tsn,
			       ntohl(rcv.rcv_ppid),
			       rcv.rcv_context);
		}
		free(data);
	}
	return 1;
}

int
main(void)
{
	struct sockaddr_in sin_s, sin_c;
	struct sockaddr_conn sconn;
#ifdef _WIN32
	SOCKET fd_c, fd_s;
#else
	int fd_c, fd_s;
#endif
	struct socket *s_c, *s_s, *s_l;
#ifdef _WIN32
	HANDLE tid_c, tid_s;
#else
	pthread_t tid_c, tid_s;
#endif
	struct sctp_sndinfo sndinfo;
	char line[LINE_LENGTH];

	usrsctp_init(0, conn_output);
	/* set up a connected UDP socket */
#ifdef _WIN32
	if ((fd_c = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		printf("socket() failed with error: %ld\n", WSAGetLastError());
	}
	if ((fd_s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		printf("socket() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if ((fd_c = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
	}
	if ((fd_s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
	}
#endif
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
	sin_s.sin_port = htons(9899);
	sin_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
	if (bind(fd_c, (struct sockaddr *)&sin_c, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("bind() failed with error: %ld\n", WSAGetLastError());
	}
	if (bind(fd_s, (struct sockaddr *)&sin_s, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("bind() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if (bind(fd_c, (struct sockaddr *)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
	}
	if (bind(fd_s, (struct sockaddr *)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
	}
#endif
#ifdef _WIN32
	if (connect(fd_c, (struct sockaddr *)&sin_s, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("connect() failed with error: %ld\n", WSAGetLastError());
	}
	if (connect(fd_s, (struct sockaddr *)&sin_c, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("connect() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if (connect(fd_c, (struct sockaddr *)&sin_s, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
	}
	if (connect(fd_s, (struct sockaddr *)&sin_c, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
	}
#endif
#ifdef _WIN32
	tid_c = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&handle_packets, (void *)&fd_c, 0, NULL);
	tid_s = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&handle_packets, (void *)&fd_s, 0, NULL);
#else
	pthread_create(&tid_c, NULL, &handle_packets, (void *)&fd_c);
	pthread_create(&tid_s, NULL, &handle_packets, (void *)&fd_s);
#endif
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	if ((s_c = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
	}
	if ((s_l = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
	}
	printf("s_c = %p, s_l = %p.\n", (void *)s_c, (void *)s_l);
	/* Bind the client side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5002);
	sconn.sconn_addr = NULL;
	if (usrsctp_bind(s_c, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
	}
	/* Bind the server side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = NULL;
	if (usrsctp_bind(s_l, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
	}
	/* Make server side passive... */
	if (usrsctp_listen(s_l, 1) < 0) {
		perror("usrsctp_listen");
	}
	/* Initiate the handshake */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = &fd_c;
	if (usrsctp_connect(s_c, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_connect");
	}
	if ((s_s = usrsctp_accept(s_l, NULL, NULL)) == NULL) {
		perror("usrsctp_accept");
	}
	printf("accepted socket %p.\n", (void *)s_s);
	usrsctp_close(s_l);
	memset(line, 'A', LINE_LENGTH);
	sndinfo.snd_sid = 1;
	sndinfo.snd_flags = 0;
	sndinfo.snd_ppid = htonl(DISCARD_PPID);
	sndinfo.snd_context = 0;
	sndinfo.snd_assoc_id = 0;
	if (usrsctp_sendv(s_c, line, LINE_LENGTH, NULL, 0, (void *)&sndinfo,
	                 (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("usrsctp_sendv");
	}
#ifdef _WIN32
	Sleep(1000);
#else
	sleep(1);
#endif
	usrsctp_close(s_c);
	usrsctp_close(s_s);
	while (usrsctp_finish() != 0) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return (0);
}
