/*
 * Copyright (C) 2011 Michael Tuexen
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

/*
 * Usage: client remote_addr remote_port [local_encaps_port] [remote_encaps_port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(__Userspace_os_Windows)
#include <unistd.h>
#endif
#include <sys/types.h>
#if !defined(__Userspace_os_Windows)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <netinet/sctp_pcb.h>
#include <usrsctp.h>

int done = 0;

static int
receive_cb(struct socket* sock, struct sctp_queued_to_read *control)
{
	struct mbuf *m;

	if (control == NULL) {
		done = 1;
		userspace_close(sock);
	} else {
		for (m = control->data; m; m = m->m_next) {
			printf("%s", m->m_data);
		}
		m_freem(control->data);
	}
	return 1;
}

int
main(int argc, char *argv[])
{
	struct socket *sock;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sctp_udpencaps encaps;
	char buffer[80];

	if (argc > 3) {
		sctp_init(atoi(argv[3]));
	} else {
		sctp_init(9899);
	}
	SCTP_BASE_SYSCTL(sctp_debug_on) = 0x0;
	SCTP_BASE_SYSCTL(sctp_blackhole) = 2;
	if ((sock = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0)) == NULL) {
		perror("userspace_socket ipv6");
	}
#if defined(CALLBACK_API)
	register_recv_cb(sock, receive_cb);
#endif
	if (argc > 4) {
		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = AF_INET6;
		encaps.sue_port = htons(atoi(argv[4]));
		if (userspace_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
			perror("setsockopt");
		}
	}
	memset((void *)&addr4, 0, sizeof(struct sockaddr_in));
	memset((void *)&addr6, 0, sizeof(struct sockaddr_in6));
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
	addr4.sin_len = sizeof(struct sockaddr_in);
	addr6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	addr4.sin_family = AF_INET;
	addr6.sin6_family = AF_INET6;
	addr4.sin_port = htons(atoi(argv[2]));
	addr6.sin6_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET6, argv[1], &addr6.sin6_addr) == 1) {
		if (userspace_connect(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6)) < 0) {
			perror("userspace_connect");
		}
	} else if (inet_pton(AF_INET, argv[1], &addr4.sin_addr) == 1) {
		if (userspace_connect(sock, (struct sockaddr *)&addr4, sizeof(struct sockaddr_in)) < 0) {
			perror("userspace_connect");
		}
	} else {
		printf("Illegal destination address.\n");
	}
	while ((fgets(buffer, sizeof(buffer), stdin) != NULL) && !done) {
		userspace_sctp_sendmsg(sock, buffer, strlen(buffer), NULL, 0, 0, 0, 0, 0, 0);
	}
	if (!done) {
		userspace_shutdown(sock, SHUT_WR);
	}
	while (!done) {
#if defined (__Userspace_os_Windows)
		Sleep(1*1000);
#else
		sleep(1);
#endif
	}
	while (userspace_finish() != 0) {
#if defined (__Userspace_os_Windows)
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return(0);
}
