/*
 * Copyright (C) 2017-2019 Felix Weinrank
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
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <usrsctp.h>
#include "../programs/programs_helper.h"


#define FUZZ_FAST 1

struct sockaddr_conn sconn;
struct socket *socket_client;

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
#if 0
	char *dump_buf;
	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		fprintf(stderr, "%s", dump_buf);
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif
	return (0);
}

static void
handle_upcall(struct socket *sock, void *arg, int flgs)
{
	fprintf(stderr, "Listening socket established, implement logic!\n");
	exit(EXIT_FAILURE);
}

int
init_fuzzer(void) {
	static uint8_t initialized = 0;
	struct sctp_event event;
	uint16_t event_types[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED_EVENT,
		SCTP_REMOTE_ERROR,
		SCTP_SHUTDOWN_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT};
	unsigned long i;

#if defined(FUZZ_FAST)
	if (initialized) {
		return 0;
	}
#endif

	usrsctp_init(0, conn_output, NULL);
	usrsctp_enable_crc32c_offload();
	/* set up a connected UDP socket */
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	usrsctp_register_address((void *)1);

	if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, 0)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	usrsctp_set_non_blocking(socket_client, 1);

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_FUTURE_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT socket_client");
			exit(EXIT_FAILURE);
		}
	}

	/* Bind the local side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = (void *)1;
	if (usrsctp_connect(socket_client, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		if (errno != EINPROGRESS) {
			perror("usrsctp_connect");
			exit(EXIT_FAILURE);
		}
	}

	usrsctp_set_upcall(socket_client, handle_upcall, NULL);

	//usrsctp_conninput((void *)1, init_ack, sizeof(init_ack), 0);
	//usrsctp_conninput((void *)1, cookie_ack, sizeof(cookie_ack), 0);



	initialized = 1;

	return (0);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
	init_fuzzer();
	//exit(0);

	usrsctp_conninput((void *)1, data, data_size, 0);

#if !defined(FUZZ_FAST)
	usrsctp_close(socket_client);
	while (usrsctp_finish() != 0) {
		//sleep(1);
	}
#endif
	return (0);
}


