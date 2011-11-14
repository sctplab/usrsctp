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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp_pcb.h>
#include <usrsctp.h>

#if defined(CALLBACK_API)
static int
receive_cb(struct socket* sock, struct sctp_queued_to_read *control)
{
	if (control) {
		printf("Message of length %u bytes received.\n", control->length);
		m_freem(control->data);
	}
	return 1;
}
#endif

int
main(int argc, char *argv[])
{
	struct socket *sock;
	struct sockaddr_in addr;
#if !defined(CALLBACK_API)
	int n, flags;
	socklen_t from_len;
	struct sctp_sndrcvinfo sinfo;
#endif

	sctp_init();
	SCTP_BASE_SYSCTL(sctp_udp_tunneling_port) = 9898;
	SCTP_BASE_SYSCTL(sctp_debug_on) = 0xffffffff;

	if ((sock = userspace_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) == NULL) {
		perror("userspace_socket");
	}
	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (userspace_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		perror("userspace_bind");
	}
	if (userspace_listen(sock, 1) < 0) {
		perror("userspace_listen");
	}
#if defined(CALLBACK_API)
	register_recv_cb(sock, receive_cb);
	while (1) {
		sleep(1);
	}
#else
	while (1) {
		memset((void *)&addr, 0, sizeof(struct sockaddr_in));
		memset((void *)&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
		from_len = (socklen_t)sizeof(struct sockaddr_in);
		flags = 0;
		n = userspace_sctp_recvmsg(sock, (void*)buffer, BUFFER_SIZE, (struct sockaddr *)&addr, &from_len, &sinfo, &flags);
		if (n > 0) {
			printf("Msg of length %d received from %s:%u on stream %d, PPID %d.\n",
			        n, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
			        sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid));
		}
	}
#endif
	userspace_close(sock);
	return (0);
}
