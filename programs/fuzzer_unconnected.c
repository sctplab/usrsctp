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
#include <dirent.h>
#include <usrsctp.h>

#define FUZZ_FAST 1

struct sockaddr_conn sconn;
struct socket *s_l;

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	char *dump_buf;

	return 0;

	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		fprintf(stderr, "%s", dump_buf);
		usrsctp_freedumpbuffer(dump_buf);
	}
	return (0);
}

static void
handle_upcall(struct socket *sock, void *arg, int flgs)
{
	fprintf(stderr, "Listening socket established, implement logic!\n");
	exit(EXIT_FAILURE);
}

void
debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
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

	usrsctp_init(0, conn_output, debug_printf);
	usrsctp_enable_crc32c_offload();
	/* set up a connected UDP socket */
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	usrsctp_register_address((void *)1);

	if ((s_l = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, 0)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	usrsctp_set_non_blocking(s_l, 1);

	/* Bind the server side. */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	sconn.sconn_addr = (void *)1;
	if (usrsctp_bind(s_l, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_FUTURE_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(s_l, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT s_l");
			exit(EXIT_FAILURE);
		}
	}

	/* Make server side passive... */
	if (usrsctp_listen(s_l, 1) < 0) {
		perror("usrsctp_listen");
		exit(EXIT_FAILURE);
	}

	usrsctp_set_upcall(s_l, handle_upcall, NULL);

	initialized = 1;

	return 0;
}


#if defined(FUZZING_MODE)
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
#else // defined(FUZZING_MODE)
int main(int argc, char *argv[])
{

	char *data;
	size_t data_size;
	FILE *file;
	DIR *d;
	struct dirent *dir;
	char file_path[255];

	if (argc != 2) {
		printf("[DIR] missing\n");
		exit(EXIT_FAILURE);
	}


	d = opendir(argv[1]);
	if (!d) {
		printf("error opening %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
#endif

	init_fuzzer();
	// magic happens here

#if defined(FUZZING_MODE)
	usrsctp_conninput((void *)1, data, data_size, 0);
#else
	while ((dir = readdir(d)) != NULL) {
		sprintf(file_path, "%s/%s", argv[1], dir->d_name);
		printf("%s \n", file_path);

		if (dir-> d_type == DT_DIR) {
			printf("skip!\n");
			continue;
		}

		file = fopen(file_path, "rb");


		if (!file) {
			perror("fopen");
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

		usrsctp_conninput((void *)1, data, data_size, 0);

		free(data);
	}
	closedir(d);
#endif

#if !defined(FUZZ_FAST) || !defined(FUZZING_MODE)
	usrsctp_close(s_l);
	while (usrsctp_finish() != 0) {
		//sleep(1);
	}
#endif

	return (0);
}
