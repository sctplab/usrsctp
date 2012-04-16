/*
 * Copyright (C) 2012 Michael Tuexen
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
 * Usage: daytime_server [local_encaps_port] [remote_encaps_port]
 */

#if defined(__Userspace_os_Windows)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if !defined(__Userspace_os_Windows)
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <netinet/sctp_pcb.h>
#include <usrsctp.h>

int
main(int argc, char *argv[])
{
	struct socket *sock, *conn_sock;
	struct sockaddr_in addr;
	struct sctp_udpencaps encaps;
	socklen_t addr_len;
	char buffer[80];
	time_t now;

	if (argc > 1) {
		sctp_init(atoi(argv[1]));
	} else {
		sctp_init(9899);
	}
	SCTP_BASE_SYSCTL(sctp_debug_on) = 0x0;
	SCTP_BASE_SYSCTL(sctp_blackhole) = 2;

	if ((sock = userspace_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == NULL) {
		perror("userspace_socket");
	}
	if (argc > 2) {
		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = AF_INET;
		encaps.sue_port = htons(atoi(argv[2]));
		if (userspace_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
			perror("setsockopt");
		}
	}
	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = htons(13);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (userspace_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		perror("userspace_bind");
	}
	if (userspace_listen(sock, 1) < 0) {
		perror("userspace_listen");
	}
	while (1) {
		addr_len = 0;
		if ((conn_sock = userspace_accept(sock, NULL, &addr_len)) == NULL) {
			continue;
		}
		time(&now);
		snprintf(buffer, sizeof(buffer), "%s", ctime(&now));
		userspace_sctp_sendmsg(conn_sock, buffer, strlen(buffer), NULL, 0, 0, 0, 0, 0, 0);
		userspace_close(conn_sock);
	}
	userspace_close(sock);
	while (userspace_finish() != 0) {
#if defined (__Userspace_os_Windows)
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return (0);
}
