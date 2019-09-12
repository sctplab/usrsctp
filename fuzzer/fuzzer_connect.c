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

#define FUZZ_VERBOSE
#define FUZZ_INTERLEAVING
#define FUZZ_EXPLICIT_EOR
#define FUZZ_STREAM_RESET
#define FUZZ_DISABLE_LINGER

#define BUFFERSIZE 256

#define SCTP_PACKED __attribute__((packed))

/* Initiate (INIT)/Initiate Ack (INIT ACK) */
struct sctp_init {
	uint32_t initiate_tag;	/* initiate tag */
	uint32_t a_rwnd;	/* a_rwnd */
	uint16_t num_outbound_streams;	/* OS */
	uint16_t num_inbound_streams;	/* MIS */
	uint32_t initial_tsn;	/* I-TSN */
	/* optional param's follow */
} SCTP_PACKED;

/*
 * SCTP Chunks
 */
struct sctp_chunkhdr {
	uint8_t chunk_type;	/* chunk type */
	uint8_t chunk_flags;	/* chunk flags */
	uint16_t chunk_length;	/* chunk length */
	/* optional params follow */
} SCTP_PACKED;

/*
 * SCTP protocol - RFC4960.
 */
struct sctphdr {
	uint16_t src_port;	/* source port */
	uint16_t dest_port;	/* destination port */
	uint32_t v_tag;		/* verification tag of packet */
	uint32_t checksum;	/* CRC32C checksum */
	/* chunks follow... */
} SCTP_PACKED;

struct sctp_init_chunk {
	struct sctp_chunkhdr ch;
	struct sctp_init init;
} SCTP_PACKED;

struct sctp_init_msg {
	struct sctphdr sh;
	struct sctp_init_chunk msg;
} SCTP_PACKED;

static char *init_ack = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00\x02\x00\x01\xf8" \
"\xc7\xa1\xb0\x4d\x00\x1c\x71\xc7\x00\x0a\xff\xff\x03\x91\x94\x1b" \
"\x80\x00\x00\x04\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80" \
"\x82\x00\x00\x00\x80\x02\x00\x24\x61\x6c\x7e\x52\x2a\xdb\xe0\xa2" \
"\xaa\x78\x25\x1e\x12\xc5\x01\x9e\x4c\x60\x16\xdf\x01\x6d\xa1\xd5" \
"\xcd\xbe\xa7\x5d\xa2\x73\xf4\x1b\x80\x04\x00\x08\x00\x03\x00\x01" \
"\x80\x03\x00\x07\x00\x80\xc1\x00\x00\x06\x00\x14\x2a\x02\xc6\xa0" \
"\x40\x15\x00\x11\x00\x00\x00\x00\x00\x00\x00\x83\x00\x05\x00\x08" \
"\xd4\xc9\x79\x53\x00\x07\x01\x80\x4b\x41\x4d\x45\x2d\x42\x53\x44" \
"\x20\x31\x2e\x31\x00\x00\x00\x00\x64\x11\x49\x00\x00\x00\x00\x00" \
"\xac\xde\x0c\x00\x00\x00\x00\x00\x60\xea\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\xb2\xd4\x38\x45\xc7\xa1\xb0\x4d\xd4\xc9\x79\x52" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00" \
"\xd4\xc9\x79\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x05\x00\x00\x00\x00\x00\x00\x00\xd9\x05\x13\x89\x01\x01\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x80\x45\x38\xd4\xb2" \
"\x00\x1c\x71\xc7\x00\x01\xff\xff\xac\x40\x9b\x94\x80\x00\x00\x04" \
"\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00" \
"\x80\x02\x00\x24\xc8\x24\x46\x8c\x7e\x88\x2e\xb7\x88\x8b\xdd\xa1" \
"\x55\x8b\xb4\xc0\x26\xe3\x21\xbb\xb0\x66\xfd\xb2\xd4\xde\xf9\x77" \
"\x4f\xe4\x7c\xbf\x80\x04\x00\x08\x00\x03\x00\x01\x80\x03\x00\x07" \
"\x00\x80\xc1\x00\x00\x0c\x00\x08\x00\x05\x00\x06\x00\x06\x00\x14" \
"\x2a\x02\xc6\xa0\x40\x15\x00\x11\x00\x00\x00\x00\x00\x00\x00\x82" \
"\x00\x05\x00\x08\xd4\xc9\x79\x52\x02\x00\x01\xf8\xc7\xa1\xb0\x4d" \
"\x00\x1c\x71\xc7\x00\x01\xff\xff\x03\x91\x94\x1b\x80\x00\x00\x04" \
"\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00" \
"\x80\x02\x00\x24\x61\x6c\x7e\x52\x2a\xdb\xe0\xa2\xaa\x78\x25\x1e" \
"\x12\xc5\x01\x9e\x4c\x60\x16\xdf\x01\x6d\xa1\xd5\xcd\xbe\xa7\x5d" \
"\xa2\x73\xf4\x1b\x80\x04\x00\x08\x00\x03\x00\x01\x80\x03\x00\x07" \
"\x00\x80\xc1\x00\x00\x06\x00\x14\x2a\x02\xc6\xa0\x40\x15\x00\x11" \
"\x00\x00\x00\x00\x00\x00\x00\x83\x00\x05\x00\x08\xd4\xc9\x79\x53" \
"\x64\x30\x8a\xb9\x7c\xe5\x93\x69\x52\xa9\xc8\xd5\xa1\x1b\x7d\xef" \
"\xea\xfa\x23\x32";

static char *cookie_ack = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00\x0b\x00\x00\x04";
static char *sctp_abort = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00\x06\x00\x00\x08\x00\x0c\x00\x04";
static char *sctp_i_data = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00" \
"\x00\x1b\x21\x73\xa3\x58\x90\xe2\xba\x9e\x8c\xfc\x08\x00\x45\x02" \
"\x04\x34\x00\x00\x40\x00\x40\x84\x9a\x0b\xd4\xc9\x79\x52\xd4\xc9" \
"\x79\x53\x65\x75\x13\x89\x11\x97\x93\x37\x26\x6c\xb7\x65\x40\x02" \
"\x04\x14\x96\xff\xad\xc1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x27\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41";
static char *common_header = "\x13\x89\xe7\xd0\xef\x38\x12\x25\x00\x00\x00\x00";

static char *init_chunk_first_bytes = "\xe7\xd0\x13\x89\x00\x00\x00\x00\x00\x00\x00\x00";

static uint32_t vtag = 0;

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
	if (length >= strlen(init_chunk_first_bytes) && memcmp(buf, init_chunk_first_bytes, strlen(init_chunk_first_bytes)) == 0) {


		struct sctp_init_msg *sctp_init = (struct sctp_init_msg*) buf;
		struct sctphdr *hdr = (struct sctphdr*) common_header;

		debug_printf("Found INIT, extracting VTAG : %d\n", sctp_init->msg.init.initiate_tag);

		hdr->v_tag = sctp_init->msg.init.initiate_tag;

	}
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
	return (1);
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
	uint16_t event_types[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED_EVENT,
		SCTP_REMOTE_ERROR,
		SCTP_SHUTDOWN_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT
	};

	debug_printf(">>>>>>>>>>>>>>>>>>> BEGINNING!\n");

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

#if defined(FUZZ_COOKIE_ECHOED) || defined (FUZZ_ESTABLISHED) || defined(FUZZ_DATA_SENT) || defined(FUZZ_DATA_RECEIVED)
	// Inject INIT-ACK
	dump_packet(init_ack, 516, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, init_ack, 516, 0);
	debug_printf(" >>> INIT_ACK\n");
#endif

#if defined(FUZZ_ESTABLISHED) || defined(FUZZ_DATA_SENT) || defined(FUZZ_DATA_RECEIVED)
	// Inject COOKIE ACK
	dump_packet(cookie_ack, 16, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, cookie_ack, 16, 0);
	debug_printf(" >>> COOKIE_ACK\n");
#endif

#if defined(FUZZ_DATA_SENT)
	const char *sendbuffer = "Geologie ist keine richtige Wissenschaft!";
	usrsctp_sendv(socket_client, sendbuffer, strlen(sendbuffer), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
#endif

#if defined(FUZZ_DATA_RECEIVED)
	// Inject COOKIE ACK
	dump_packet(sctp_i_data, 1102, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, sctp_i_data, 1102, 0);
	debug_printf(" >>> I_DATA\n");
#endif

	// Inject fuzzed packet
	pktbuf = malloc(data_size + 12);
	memcpy(pktbuf, common_header, 12); // common header
	memcpy(pktbuf + 12, data, data_size);
	dump_packet(pktbuf, data_size + 12, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, pktbuf, data_size + 12, 0);

	usrsctp_close(socket_client);

	free(pktbuf);
	return (0);
}


