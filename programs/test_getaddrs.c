/*
 * Copyright (C) 2026 Michael Tuexen
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
 * ARE DISCLAIMED.      IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Regression test for the address getter/free helpers. On a bound but
 * unconnected socket usrsctp_getpaddrs() returns 0 with no peer addresses.
 * It must leave *raddrs set to NULL so that the matching usrsctp_freepaddrs()
 * call becomes a no-op instead of freeing an unrelated (or already freed)
 * pointer. The same contract holds for usrsctp_getladdrs()/usrsctp_freeladdrs().
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#include "usrsctp.h"

int
main(void)
{
	struct socket *so;
	struct sockaddr_in addr;
	struct sockaddr *addrs;
	int result = 0;
	int n;

	usrsctp_init(0, NULL, NULL);
	if ((so = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
		return (EXIT_FAILURE);
	}
	memset(&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (usrsctp_bind(so, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		perror("usrsctp_bind");
		usrsctp_close(so);
		return (EXIT_FAILURE);
	}

	/* Local addresses exist: pointer is set and must be freeable. */
	addrs = NULL;
	if ((n = usrsctp_getladdrs(so, 0, &addrs)) < 0) {
		perror("usrsctp_getladdrs");
		result = 1;
	} else {
		usrsctp_freeladdrs(addrs);
	}

	/* No association: getpaddrs() returns 0 and must set *raddrs to NULL. */
	addrs = (struct sockaddr *)(void *)so; /* poison with a non-NULL value */
	n = usrsctp_getpaddrs(so, 0, &addrs);
	if (n < 0) {
		perror("usrsctp_getpaddrs");
		result = 1;
	} else if (addrs != NULL) {
		fprintf(stderr, "usrsctp_getpaddrs() returned %d but left *raddrs non-NULL\n", n);
		result = 1;
	}
	/* Must be a no-op, not a free of the poisoned pointer. */
	usrsctp_freepaddrs(addrs);

	/* Passing NULL to the free helpers must be a no-op. */
	usrsctp_freeladdrs(NULL);
	usrsctp_freepaddrs(NULL);

	usrsctp_close(so);
	while (usrsctp_finish() != 0) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	if (result == 0) {
		printf("test_getaddrs: PASSED\n");
		return (EXIT_SUCCESS);
	} else {
		printf("test_getaddrs: FAILED\n");
		return (EXIT_FAILURE);
	}
}
