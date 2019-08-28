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
#include <sys/time.h>
#include <usrsctp.h>

//#define FUZZ_VERBOSE
//#define FUZZ_FAST
#define FUZZ_INTERLEAVING
#define FUZZ_EXPLICIT_EOR
#define FUZZ_STREAM_RESET
#define FUZZ_DISABLE_LINGER

#define BUFFERSIZE 256

static const char *init_ack = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00\x02\x00\x01\x4c" \
"\x20\x0f\x67\x0d\x00\x02\x00\x00\x00\x04\x00\x04\xbd\xf0\x8d\x18" \
"\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00" \
"\x80\x02\x00\x24\xfd\x30\xc7\x17\x34\x27\x17\x1c\xa2\xc6\x78\x20" \
"\x62\xc3\xa1\x3f\xb6\x86\x92\x42\xc5\x0b\xb6\x36\xd7\xf6\xf4\x19" \
"\xee\xd3\xc9\x1e\x80\x04\x00\x06\x00\x01\x00\x00\x80\x03\x00\x06" \
"\x80\xc1\x00\x00\x00\x07\x00\xf4\x4b\x41\x4d\x45\x2d\x42\x53\x44" \
"\x20\x31\x2e\x31\x00\x00\x00\x00\x25\xfa\x5e\x5d\x00\x00\x00\x00" \
"\xe6\xc3\x0a\x00\x00\x00\x00\x00\x60\xea\x00\x00\x54\x6f\x2d\xff" \
"\xd1\x7f\x68\x2a\x00\x00\x00\x01\x20\x0f\x67\x0d\x80\x3b\x00\x00" \
"\xc0\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00" \
"\x80\x3b\x00\x00\xc0\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x04\x00\x00\x00\x00\x00\x00\x00\x13\x88\x13\x88\x00\x00\x01\x00" \
"\x01\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x14\x01\x00\x00\x00" \
"\x00\x00\x20\x00\x00\x08\x00\x08\x00\x00\x00\x01\x02\x00\x01\x4c" \
"\x20\x0f\x67\x0d\x00\x02\x00\x00\x00\x04\x00\x04\xbd\xf0\x8d\x18" \
"\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00" \
"\x80\x02\x00\x24\xfd\x30\xc7\x17\x34\x27\x17\x1c\xa2\xc6\x78\x20" \
"\x62\xc3\xa1\x3f\xb6\x86\x92\x42\xc5\x0b\xb6\x36\xd7\xf6\xf4\x19" \
"\xee\xd3\xc9\x1e\x80\x04\x00\x06\x00\x01\x00\x00\x80\x03\x00\x06" \
"\x80\xc1\x00\x00\x41\xc3\xed\x62\x2c\x1c\x3c\x03\x41\x6d\x17\xc8" \
"\xd8\x64\xff\xe2\x25\xd6\x81\x9e";

static const char *cookie_ack = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00\x0b\x00\x00\x04";
static const char *common_header = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00";

#ifdef FUZZ_VERBOSE
static char *dump_buf;
void
debug_printf(const char *format, ...)
{
	static struct timeval time_main;

	va_list ap;
	struct timeval time_now;
	struct timeval time_delta;

	if (time_main.tv_sec == 0  && time_main.tv_usec == 0) {
		gettimeofday(&time_main, NULL);
	}

	gettimeofday(&time_now, NULL);
	timersub(&time_now, &time_main, &time_delta);

	fprintf(stderr, "[%u.%03u] ", (unsigned int) time_delta.tv_sec, (unsigned int) time_delta.tv_usec / 1000);

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}
#else
void
debug_printf(const char *format, ...)
{
	// Nothing
}
#endif

static void
dump_packet(const void *buffer, size_t bufferlen, int inout) {
#ifdef FUZZ_VERBOSE
	if ((dump_buf = usrsctp_dumppacket(buffer, bufferlen, inout)) != NULL) {
		fprintf(stderr, "%s", dump_buf);
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif
}


static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	dump_packet(buf, length, SCTP_DUMP_OUTBOUND);
	return (0);
}


static void
handle_upcall(struct socket *sock, void *arg, int flgs)
{
	debug_printf("handle_upcall() called - implement logic!\n");
	int events = usrsctp_get_events(sock);
	while (events & SCTP_EVENT_READ) {
		struct sctp_recvv_rn rn;
		ssize_t n;
		struct sockaddr_in addr;
		char *buf = calloc(1, BUFFERSIZE);
		int flags = 0;
		socklen_t len = (socklen_t)sizeof(struct sockaddr_in);
		unsigned int infotype = 0;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));
		n = usrsctp_recvv(sock, buf, BUFFERSIZE, (struct sockaddr *) &addr, &len, (void *)&rn, &infolen, &infotype, &flags);

		free(buf);
		if (n <= 0) {
			break;
		}

		events = usrsctp_get_events(sock);
	}
}


int
initialize_fuzzer(void) {
#ifdef FUZZ_VERBOSE
	usrsctp_init(0, conn_output, debug_printf);
#else
	usrsctp_init(0, conn_output, NULL);
#endif
	usrsctp_enable_crc32c_offload();
	/* set up a connected UDP socket */
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	usrsctp_register_address((void *)1);
	debug_printf("usrsctp initialized\n");
	return 1;
}


int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size)
{
	static int initialized;
	char *pktbuf;
	struct sockaddr_conn sconn;
	struct socket *socket_client;
	struct linger so_linger;
	struct sctp_event event;
	unsigned long i;
	uint8_t fuzzing_stage, split_packets, split_size;
	size_t offset;
	uint16_t event_types[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED_EVENT,
		SCTP_REMOTE_ERROR,
		SCTP_SHUTDOWN_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT
	};

#if defined(FUZZ_EXPLICIT_EOR) || defined(FUZZ_INTERLEAVING)
	int enable;
#endif
#if defined(FUZZ_STREAM_RESET) || defined(FUZZ_INTERLEAVING)
	struct sctp_assoc_value assoc_val;
#endif

	if (!initialized) {
		initialized = initialize_fuzzer();
	}

	if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, 0)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}

	usrsctp_set_non_blocking(socket_client, 1);

	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	if (usrsctp_setsockopt(socket_client, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) < 0) {
		perror("usrsctp_setsockopt 1");
		exit(EXIT_FAILURE);
	}

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

#if defined(FUZZ_EXPLICIT_EOR)
	enable = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR socket_client");
		exit(EXIT_FAILURE);
	}
#endif // defined(FUZZ_EXPLICIT_EOR)

#if defined(FUZZ_STREAM_RESET)
	assoc_val.assoc_id = SCTP_ALL_ASSOC;
	assoc_val.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_val, sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET socket_client");
		exit(EXIT_FAILURE);
	}
#endif //defined(FUZZ_STREAM_RESET)


#if defined(FUZZ_INTERLEAVING)
#if !defined(SCTP_INTERLEAVING_SUPPORTED)
#define SCTP_INTERLEAVING_SUPPORTED 0x00001206
#endif // !defined(SCTP_INTERLEAVING_SUPPORTED)
	enable = 2;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &enable, sizeof(enable)) < 0) {
		perror("usrsctp_setsockopt SCTP_FRAGMENT_INTERLEAVE socket_client");
		exit(EXIT_FAILURE);
	}

	memset(&assoc_val, 0, sizeof(assoc_val));
	assoc_val.assoc_value = 1;
	if (usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_val, sizeof(assoc_val)) < 0) {
		perror("usrsctp_setsockopt SCTP_INTERLEAVING_SUPPORTED socket_client");
		exit(EXIT_FAILURE);
	}
#endif // defined(FUZZ_INTERLEAVING)

	usrsctp_set_upcall(socket_client, handle_upcall, NULL);

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

	if (data_size > 10) {
		fuzzing_stage = data[0] % 2;
		split_packets = (data[1] % 4);
		split_size = data_size / (split_packets + 1);
	} else {
		fuzzing_stage = 1;
		split_packets = 0;
	}

	//printf("Stage %d - Packets %d\n", fuzzing_stage, split_packets);

	// Send INIT
	dump_packet(init_ack, 344, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, init_ack, 344, 0);

	// Send COOKIE ACK
	if (fuzzing_stage >= 1) {
		dump_packet(cookie_ack, 16, SCTP_DUMP_INBOUND);
		usrsctp_conninput((void *)1, cookie_ack, 16, 0);
	}

	// concat common header and fuzzer input
	offset = 0;
	pktbuf = malloc(data_size + 12);
	memcpy(pktbuf, common_header, 12);

	// splitting logic
	while (split_packets > 0) {
		memcpy(pktbuf + 12, data + offset , split_size);
		offset += split_size;
		split_packets--;

		dump_packet(pktbuf, data_size + 12, SCTP_DUMP_INBOUND);
		usrsctp_conninput((void *)1, pktbuf, data_size + 12, 0);
	}

	memcpy(pktbuf + 12, data + offset, data_size - offset);
	dump_packet(pktbuf, data_size + 12, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, pktbuf, data_size + 12, 0);

	usrsctp_close(socket_client);
	free(pktbuf);
	return (0);
}


