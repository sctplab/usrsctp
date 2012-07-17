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

#if defined(__Userspace_os_Windows)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if !defined(__Userspace_os_Windows)
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
#define BUFFER_SIZE 80
#define DISCARD_PPID 39

static void *
handle_packets(void *arg)
{
#if defined(__Userspace_os_Windows)
	SOCKET *fdp;
#else
	int *fdp;
#endif
	char *buf;
	ssize_t length;

#if defined(__Userspace_os_Windows)
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
			usrsctp_conninput(fdp, buf, (size_t)length, 0);
		}
	}
	free(buf);
	return (NULL);
}

static int
conn_output(void *addr, void *buffer, size_t length, uint8_t tos, uint8_t set_df)
{
#if defined(__Userspace_os_Windows)
	SOCKET *fdp;
#else
	int *fdp;
#endif

#if defined(__Userspace_os_Windows)
	fdp = (SOCKET *)addr;
#else
	fdp = (int *)addr;
#endif
#if defined(__Userspace_os_Windows)
	if (send(*fdp, buffer, length, 0) == SOCKET_ERROR) {
		return(WSAGetLastError());
#else
	if (send(*fdp, buffer, length, 0) < 0) {
		return(errno);
#endif
	} else {
		return (0);
	}
}

static int
receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{

	if (data) {
		if (flags & MSG_NOTIFICATION) {
			printf("Notification of length %d received.\n", (int)datalen);
		} else {
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
main(int argc, char *argv[])
{
	struct sockaddr_in sin;
	struct sockaddr_conn sconn;
#if defined(__Userspace_os_Windows)
	SOCKET fd;
#else
	int fd;
#endif
	struct socket *s;
#if defined(__Userspace_os_Windows)
	HANDLE tid;
#else
	pthread_t tid;
#endif
	struct sctp_sndinfo sndinfo;
	char buffer[BUFFER_SIZE];

	usrsctp_init(0, conn_output);
	/* set up a connected UDP socket */
#if defined(__Userspace_os_Windows)
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		printf("socket() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
	}
#endif
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin.sin_len = sizeof(struct sockaddr_in);
#endif
	sin.sin_port = htons(atoi(argv[2]));
	sin.sin_addr.s_addr = inet_addr(argv[1]);
#if defined(__Userspace_os_Windows)
	if (bind(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("bind() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if (bind(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
	}
#endif
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	sin.sin_len = sizeof(struct sockaddr_in);
#endif
	sin.sin_port = htons(atoi(argv[4]));
	sin.sin_addr.s_addr = inet_addr(argv[3]);
#if defined(__Userspace_os_Windows)
	if (connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("connect() failed with error: %ld\n", WSAGetLastError());
	}
#else
	if (connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
	}
#endif
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(0x0);
#endif
#if defined(__Userspace_os_Windows)
	tid = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&handle_packets, (void *)&fd, 0, NULL);
#else
	pthread_create(&tid, NULL, &handle_packets, (void *)&fd);
#endif
	if ((s = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
	}
#if 1
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SIN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(0);
	sconn.sconn_addr = NULL;
	if (usrsctp_bind(s, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
	}
#endif
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SIN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = &fd;
	if (usrsctp_connect(s, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_connect");
	}
	memset(buffer, 'A', BUFFER_SIZE);
	sndinfo.snd_sid = 1;
	sndinfo.snd_flags = 0;
	sndinfo.snd_ppid = htonl(DISCARD_PPID);
	sndinfo.snd_context = 0;
	sndinfo.snd_assoc_id = 0;
	if (usrsctp_sendv(s, buffer, BUFFER_SIZE, NULL, 0, (void *)&sndinfo,
	                  (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("usrsctp_sendv");
	}
	usrsctp_close(s);
	while (usrsctp_finish() != 0) {
#if defined (__Userspace_os_Windows)
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return (0);
}
