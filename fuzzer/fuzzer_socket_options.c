/*
 * Copyright (C) 2026 The usrsctp Authors
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * fuzzer_socket_options: socket-option matrix harness.
 *
 * Threat model (why this harness should find bugs):
 * - Untrusted input #1: SCTP socket options are routinely derived from
 *   attacker-influenced state (peer-advertised parameters, heartbeat/RTT
 *   values, application config fed from the wire). setsockopt()/getsockopt()
 *   handlers in sctp_usrreq.c do heavy arithmetic and buffer handling on
 *   those values (AUTH key tables, HMAC ident lists, RTO bounds, PR
 *   policies, CC and stream-scheduler module switches).
 * - Untrusted input #2: raw inbound SCTP packets on an established
 *   association, plus attacker-shaped PR-SCTP/unordered send parameters.
 * - Both cross the trust boundary in usrsctp_setsockopt/usrsctp_getsockopt,
 *   usrsctp_sendv and usrsctp_conninput, all called directly here.
 *
 * Coverage rationale: per-target 20261111 reports show sctp_usrreq.c at
 * 6,080/6,532 dark lines, sctp_cc_functions.c 1,208/1,228 (CC modules are
 * only selectable via SCTP_PLUGGABLE_CC), sctp_ss_functions.c 461/579
 * (schedulers only via SCTP_STREAM_SCHEDULER), user_socket.c 1,677/2,248
 * and sctp_peeloff.c 99/99 (never called by the incumbents). No incumbent
 * harness touches the option surface beyond NODELAY/INTERLEAVING/
 * RESET_STREAMS/REUSE_PORT/EVENT.
 *
 * Input layout (all reads bounds-checked; overrun ends that phase only):
 *   u8 flags         FUZZ_O_* behaviour bits
 *   u8 n_pre         pre-connect setsockopt count (<=12)
 *   n_pre x option record
 *   u8 n_ticks       timer tick count (<=4, only with FUZZ_O_TIMER_TICKS)
 *   n_ticks x u8 ms10 (x10ms, <=200)
 *   u8 n_post        post-handshake setsockopt count (<=12)
 *   n_post x option record (assoc-scoped)
 *   u8 n_chunks      injected packet count (<=32)
 *   n_chunks x { u8 cflags; u16 len; len bytes }  (cflags & 1 = sendv first)
 *   u8 n_sends       sendv count (<=4)
 *   n_sends x { u16 len(<=4096); u16 sid; u16 sndflags; u32 ppid;
 *               u32 context; u16 pr_policy; u32 pr_value; u16 authkey }
 *   u8 n_gets        getsockopt sweep count (<=8)
 *   n_gets x u8 get_id
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <usrsctp.h>
#include "../programs/programs_helper.h"

#define FUZZ_O_AUTH_PRELUDE   (1 << 0)
#define FUZZ_O_CC_SWITCH      (1 << 1)
#define FUZZ_O_SS_SWITCH      (1 << 2)
#define FUZZ_O_LOCAL_SHUTDOWN (1 << 3)
#define FUZZ_O_PEER_SHUTDOWN  (1 << 4)
#define FUZZ_O_PEEL_OFF       (1 << 5)
#define FUZZ_O_TIMER_TICKS    (1 << 6)
#define FUZZ_O_RESERVED       (1 << 7)

#define FUZZ_MAX_OPTIONS 12
#define FUZZ_MAX_CHUNKS 32
#define FUZZ_MAX_CHUNK_LEN 1200
#define FUZZ_MAX_SENDS 4
#define FUZZ_MAX_SEND_LEN 4096
#define FUZZ_MAX_GETS 8
#define FUZZ_MAX_TICKS 4
#define FUZZ_MAX_KEY_LEN 64
#define BUFFER_SIZE 4096
#define COMMON_HEADER_SIZE 12

static uint32_t assoc_vtag = 0;

/*
 * Options constants from usrsctplib/netinet/sctp.h that are not exposed in
 * the public usrsctp.h (same approach as fuzzer_fragment.c, which defines
 * SCTP_INTERLEAVING_SUPPORTED locally).
 */
#define SCTP_PLUGGABLE_CC            0x00001202
#define SCTP_CMT_ON_OFF              0x00001200
#define SCTP_CMT_USE_DAC             0x00001201
#define SCTP_STREAM_SCHEDULER        0x00001203
#define SCTP_STREAM_SCHEDULER_VALUE  0x00001204
#define SCTP_CC_OPTION               0x00001205
#define SCTP_INTERLEAVING_SUPPORTED  0x00001206
#define SCTP_GET_SNDBUF_USE          0x00001101
#define SCTP_GET_LOCAL_ADDR_SIZE     0x00008005
#define SCTP_GET_REMOTE_ADDR_SIZE    0x00008006

//#define FUZZ_VERBOSE

#ifdef FUZZ_VERBOSE
#define fuzzer_printf(...) debug_printf(__VA_ARGS__)
#else
#define fuzzer_printf(...)
#endif

/* option interpreter op codes */
#define FUZZ_OP_RTOINFO             0x01
#define FUZZ_OP_ASSOCINFO           0x02
#define FUZZ_OP_MAXSEG              0x03
#define FUZZ_OP_DELAYED_SACK        0x04
#define FUZZ_OP_PDP                 0x05
#define FUZZ_OP_FRAGMENT_INTERLEAVE 0x06
#define FUZZ_OP_CC_SWITCH           0x07
#define FUZZ_OP_SS_SWITCH           0x08
#define FUZZ_OP_AUTH_KEY            0x09
#define FUZZ_OP_AUTH_CHUNK          0x0a
#define FUZZ_OP_AUTH_ACTIVE_KEY     0x0b
#define FUZZ_OP_AUTH_DEACTIVATE_KEY 0x0c
#define FUZZ_OP_HMAC_IDENT          0x0d
#define FUZZ_OP_SUPPORTED_TOGGLE    0x0e
#define FUZZ_OP_PEER_ADDR_PARAMS    0x0f
#define FUZZ_OP_UDP_ENCAPS          0x10
#define FUZZ_OP_AUTOCLOSE           0x11
#define FUZZ_OP_MISC_U32            0x12
#define FUZZ_OP_DEFAULT_SNDINFO     0x13
#define FUZZ_OP_DEFAULT_PRINFO      0x14
#define FUZZ_OP_ENABLE_STREAM_RESET 0x15
#define FUZZ_OP_INITMSG             0x16
#define FUZZ_OP_CMT                 0x17
#define FUZZ_OP_EVENT               0x18
#define FUZZ_OP_SYSCTL              0x19
#define FUZZ_OP_ADD_STREAMS         0x1a
#define FUZZ_OP_RESET_STREAMS       0x1b
#define FUZZ_OP_SET_PEER_PRIMARY    0x1c
#define FUZZ_OP_INTERLEAVING        0x1d

/* getsockopt sweep ids */
#define FUZZ_GET_STATUS            0x01
#define FUZZ_GET_TIMEOUTS          0x02
#define FUZZ_GET_ASSOC_ID_LIST     0x03
#define FUZZ_GET_LOCAL_AUTH_CHUNKS 0x04
#define FUZZ_GET_PEER_AUTH_CHUNKS  0x05
#define FUZZ_GET_SNDBUF_USE        0x06
#define FUZZ_GET_PR_ASSOC_STATUS   0x07
#define FUZZ_GET_PR_STREAM_STATUS  0x08
#define FUZZ_GET_PEER_ADDR_INFO    0x09
#define FUZZ_GET_LOCAL_ADDR_SIZE   0x0a
#define FUZZ_GET_REMOTE_ADDR_SIZE  0x0b

static void
dump_packet(const void *buffer, size_t bufferlen, int inout)
{
#ifdef FUZZ_VERBOSE
	static char *dump_buf;
	if ((dump_buf = usrsctp_dumppacket(buffer, bufferlen, inout)) != NULL) {
		fprintf(stderr, "%s", dump_buf);
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif
}

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	struct sctp_init_chunk *init_chunk;
	const char *init_chunk_first_bytes = "\x13\x88\x13\x89\x00\x00\x00\x00\x00\x00\x00\x00\x01";

	/* Looking for the outgoing VTAG. */
	if ((length >= (COMMON_HEADER_SIZE + 16)) && (memcmp(buf, init_chunk_first_bytes, COMMON_HEADER_SIZE) == 0)) {
		init_chunk = (struct sctp_init_chunk *) ((char *)buf + sizeof(struct sctp_common_header));
		fuzzer_printf("Found outgoing INIT, extracting VTAG : %u\n", init_chunk->initiate_tag);
		assoc_vtag = init_chunk->initiate_tag;
	}

	dump_packet(buf, length, SCTP_DUMP_OUTBOUND);
	return (0);
}

static void
handle_upcall(struct socket *sock, void *arg, int flgs)
{
	int events = usrsctp_get_events(sock);

	while (events & SCTP_EVENT_READ) {
		struct sctp_recvv_rn rn;
		ssize_t n;
		struct sockaddr_in addr;
		char *buf = calloc(1, BUFFER_SIZE);
		int flags = 0;
		socklen_t len = (socklen_t)sizeof(struct sockaddr_in);
		unsigned int infotype = 0;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);

		if (buf == NULL) {
			break;
		}
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));
		n = usrsctp_recvv(sock, buf, BUFFER_SIZE, (struct sockaddr *)&addr, &len, (void *)&rn, &infolen, &infotype, &flags);
		fuzzer_printf("usrsctp_recvv() - returned %zd\n", n);
		free(buf);
		if (n <= 0) {
			break;
		}
		events = usrsctp_get_events(sock);
	}
}

/* ---- bounds-checked input reader ---- */

struct fuzz_cursor {
	const uint8_t *data;
	size_t size;
	size_t pos;
};

static int
rd_bytes(struct fuzz_cursor *fc, void *out, size_t n)
{
	if (fc->pos + n > fc->size) {
		return (0);
	}
	memcpy(out, fc->data + fc->pos, n);
	fc->pos += n;
	return (1);
}

static int
rd_u8(struct fuzz_cursor *fc, uint8_t *v)
{
	return (rd_bytes(fc, v, 1));
}

static int
rd_u16(struct fuzz_cursor *fc, uint16_t *v)
{
	uint8_t b[2];
	if (!rd_bytes(fc, b, 2)) {
		return (0);
	}
	*v = ((uint16_t)b[0] << 8) | b[1];
	return (1);
}

static int
rd_u32(struct fuzz_cursor *fc, uint32_t *v)
{
	uint8_t b[4];
	if (!rd_bytes(fc, b, 4)) {
		return (0);
	}
	*v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
	return (1);
}


/* ---- fixed handshake fixtures (same transcripts as the incumbents) ---- */

static char fuzz_init_ack[] =
	"\x13\x89\x13\x88\x49\xa4\xac\xb2\x00\x00\x00\x00\x02\x00\x01\xb4"
	"\x2b\xe8\x47\x40\x00\x1c\x71\xc7\xff\xff\xff\xff\xed\x69\x58\xec"
	"\xc0\x06\x00\x08\x00\x00\x07\xc4\x80\x00\x00\x04\xc0\x00\x00\x04"
	"\x80\x08\x00\x0b\xc0\xc2\x0f\xc1\x80\x82\x40\x00\x80\x02\x00\x24"
	"\x40\x39\xcf\x32\xd6\x60\xcf\xfa\x3f\x2f\xa9\x52\xed\x2b\xf2\xe6"
	"\x2f\xb7\x81\x96\xf8\xda\xe9\xa0\x62\x01\x79\xe1\x0d\x5f\x38\xaa"
	"\x80\x04\x00\x08\x00\x03\x00\x01\x80\x03\x00\x06\x80\xc1\x00\x00"
	"\x00\x07\x01\x50\x4b\x41\x4d\x45\x2d\x42\x53\x44\x20\x31\x2e\x31"
	"\x00\x00\x00\x00\x64\xdb\x63\x00\x00\x00\x00\x00\xc9\x76\x03\x00"
	"\x00\x00\x00\x00\x60\xea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\xb2\xac\xa4\x49\x2b\xe8\x47\x40\xd4\xc9\x79\x52\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\xd4\xc9\x79\x53"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00"
	"\x00\x00\x00\x00\x5a\x76\x13\x89\x01\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x01\x00\x00\x62\x49\xa4\xac\xb2\x00\x1c\x71\xc7"
	"\x00\x01\xff\xff\x82\xe6\xc8\x44\x80\x00\x00\x04\xc0\x00\x00\x04"
	"\x80\x08\x00\x0b\xc0\xc2\x0f\xc1\x80\x82\x40\x00\x80\x02\x00\x24"
	"\xb6\xbb\xb5\x7f\xbb\x4b\x0e\xb5\x42\xf6\x75\x18\x4f\x79\x0f\x24"
	"\x1c\x44\x0b\xd6\x62\xa9\x84\xe7\x2c\x3c\x7f\xad\x1b\x67\x81\x57"
	"\x80\x04\x00\x08\x00\x03\x00\x01\x80\x03\x00\x06\x80\xc1\x00\x00"
	"\x00\x0c\x00\x06\x00\x05\x00\x00\x02\x00\x01\xb4\x2b\xe8\x47\x40"
	"\x00\x1c\x71\xc7\x00\x01\xff\xff\xed\x69\x58\xec\xc0\x06\x00\x08"
	"\x00\x00\x07\xc4\x80\x00\x00\x04\xc0\x00\x00\x04\x80\x08\x00\x0b"
	"\xc0\xc2\x0f\xc1\x80\x82\x40\x00\x80\x02\x00\x24\x40\x39\xcf\x32"
	"\xd6\x60\xcf\xfa\x3f\x2f\xa9\x52\xed\x2b\xf2\xe6\x2f\xb7\x81\x96"
	"\xf8\xda\xe9\xa0\x62\x01\x79\xe1\x0d\x5f\x38\xaa\x80\x04\x00\x08"
	"\x00\x03\x00\x01\x80\x03\x00\x06\x80\xc1\x00\x00\x81\xe1\x1e\x81"
	"\xea\x41\xeb\xf0\x12\xd9\x74\xbe\x13\xfd\x4b\x6c\x5c\xa2\x8f\x00";
static char fuzz_cookie_ack[] =
	"\x13\x89\x13\x88\xb7\x0d\x32\x66\x00\x00\x00\x00\x0b\x00\x00\x04";
static char fuzz_common_header[] =
	"\x13\x89\x13\x88\xb7\x0d\x32\x66\x00\x00\x00\x00";
static char fuzz_shutdown_chunk[] =
	"\x07\x00\x00\x08\x00\x00\x00\x01";
static char fuzz_shutdown_ack_chunk[] =
	"\x08\x00\x00\x04";
static char fuzz_shutdown_complete_chunk[] =
	"\x0e\x01\x00\x08";

static void
apply_option_more(struct socket *sock, struct fuzz_cursor *fc, sctp_assoc_t assoc_id);

static void
fill_conn_addr(struct sockaddr_conn *sconn, uint16_t port)
{
	memset(sconn, 0, sizeof(struct sockaddr_conn));
	sconn->sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn->sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn->sconn_port = htons(port);
	sconn->sconn_addr = (void *)1;
}

/* ---- option interpreter: one op per call, payload read from the cursor ---- */

static void
apply_option(struct socket *sock, struct fuzz_cursor *fc, uint8_t phase)
{
	sctp_assoc_t assoc_id;
	uint8_t op;

	if (!rd_u8(fc, &op)) {
		return;
	}
	/* ops applied in the post-handshake phase target the live association */
	assoc_id = (phase == 1) ? (sctp_assoc_t)SCTP_CURRENT_ASSOC : (sctp_assoc_t)SCTP_FUTURE_ASSOC;

	switch (op) {
	case FUZZ_OP_RTOINFO: {
		struct sctp_rtoinfo rto;
		uint32_t v0, v1, v2;
		if (rd_u32(fc, &v0) && rd_u32(fc, &v1) && rd_u32(fc, &v2)) {
			memset(&rto, 0, sizeof(rto));
			rto.srto_assoc_id = assoc_id;
			rto.srto_initial = v0 % 600001;
			rto.srto_max = v1 % 600001;
			rto.srto_min = v2 % 600001;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RTOINFO, &rto, sizeof(rto));
		}
		break;
	}
	case FUZZ_OP_ASSOCINFO: {
		struct sctp_assocparams ap;
		uint32_t v0, v1;
		uint16_t v2, v3;
		if (rd_u32(fc, &v0) && rd_u32(fc, &v1) && rd_u16(fc, &v2) && rd_u16(fc, &v3)) {
			memset(&ap, 0, sizeof(ap));
			ap.sasoc_assoc_id = assoc_id;
			ap.sasoc_peer_rwnd = v0;
			ap.sasoc_cookie_life = v1;
			ap.sasoc_asocmaxrxt = v2;
			ap.sasoc_number_peer_destinations = v3;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ASSOCINFO, &ap, sizeof(ap));
		}
		break;
	}
	case FUZZ_OP_MAXSEG:
	case FUZZ_OP_PDP:
	case FUZZ_OP_AUTOCLOSE: {
		struct sctp_assoc_value av;
		uint32_t v;
		int opt;
		if (!rd_u32(fc, &v)) {
			break;
		}
		memset(&av, 0, sizeof(av));
		av.assoc_id = assoc_id;
		av.assoc_value = v;
		opt = (op == FUZZ_OP_MAXSEG) ? SCTP_MAXSEG : ((op == FUZZ_OP_PDP) ? SCTP_PARTIAL_DELIVERY_POINT : SCTP_AUTOCLOSE);
		usrsctp_setsockopt(sock, IPPROTO_SCTP, opt, &av, sizeof(av));
		break;
	}
	case FUZZ_OP_DELAYED_SACK: {
		struct sctp_sack_info si;
		uint32_t delay, freq;
		if (rd_u32(fc, &delay) && rd_u32(fc, &freq)) {
			memset(&si, 0, sizeof(si));
			si.sack_assoc_id = assoc_id;
			si.sack_delay = delay % 501;
			si.sack_freq = freq % 6;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_DELAYED_SACK, &si, sizeof(si));
		}
		break;
	}
	case FUZZ_OP_CC_SWITCH: {
		struct sctp_assoc_value av;
		uint32_t algo, sub, subval;
		if (!rd_u32(fc, &algo)) {
			break;
		}
		memset(&av, 0, sizeof(av));
		av.assoc_id = assoc_id;
		av.assoc_value = algo % 4;
		usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_PLUGGABLE_CC, &av, sizeof(av));
		/* CC module sub-options (RTCC setmode, DCCC/ECN, steady step) */
		if (rd_u32(fc, &sub) && rd_u32(fc, &subval)) {
			struct sctp_cc_option cc_opt;
			memset(&cc_opt, 0, sizeof(cc_opt));
			cc_opt.option = (int)(0x2000 + (sub % 3));
			cc_opt.aid_value.assoc_id = assoc_id;
			cc_opt.aid_value.assoc_value = subval;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_CC_OPTION, &cc_opt, sizeof(cc_opt));
		}
		break;
	}
	case FUZZ_OP_SS_SWITCH: {
		struct sctp_assoc_value av;
		uint32_t sched, sval;
		if (rd_u32(fc, &sched) && rd_u32(fc, &sval)) {
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = sched % 6;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_STREAM_SCHEDULER, &av, sizeof(av));
			av.assoc_value = sval;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_STREAM_SCHEDULER_VALUE, &av, sizeof(av));
		}
		break;
	}
	default:
		apply_option_more(sock, fc, assoc_id);
		break;
	}
}

static void
apply_option_more(struct socket *sock, struct fuzz_cursor *fc, sctp_assoc_t assoc_id)
{
	uint8_t buffer[512];
	uint8_t op;

	/* the op byte was consumed by apply_option() */
	if (!rd_u8(fc, &op)) {
		return;
	}

	switch (op) {
	case FUZZ_OP_AUTH_KEY: {
		uint8_t akbuf[sizeof(struct sctp_authkey) + FUZZ_MAX_KEY_LEN];
		struct sctp_authkey *ak = (struct sctp_authkey *)(void *)akbuf;
		uint16_t keyid;
		uint8_t keylen;
		if (rd_u16(fc, &keyid) && rd_u8(fc, &keylen)) {
			if (keylen > FUZZ_MAX_KEY_LEN) {
				keylen = FUZZ_MAX_KEY_LEN;
			}
			if (!rd_bytes(fc, buffer, keylen)) {
				break;
			}
			memset(akbuf, 0, sizeof(akbuf));
			ak->sca_keynumber = keyid % 8;
			ak->sca_keylength = keylen;
			ak->sca_assoc_id = assoc_id;
			memcpy(ak->sca_key, buffer, keylen);
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_AUTH_KEY, akbuf, sizeof(struct sctp_authkey) + keylen);
		}
		break;
	}
	case FUZZ_OP_AUTH_CHUNK: {
		struct sctp_authchunk ac;
		uint8_t c;
		if (rd_u8(fc, &c)) {
			memset(&ac, 0, sizeof(ac));
			ac.sauth_chunk = c;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &ac, sizeof(ac));
		}
		break;
	}
	case FUZZ_OP_AUTH_ACTIVE_KEY:
	case FUZZ_OP_AUTH_DEACTIVATE_KEY: {
		struct sctp_authkeyid akid;
		uint16_t keyid;
		if (rd_u16(fc, &keyid)) {
			memset(&akid, 0, sizeof(akid));
			akid.scact_assoc_id = assoc_id;
			akid.scact_keynumber = keyid;
			usrsctp_setsockopt(sock, IPPROTO_SCTP,
			    (op == FUZZ_OP_AUTH_ACTIVE_KEY) ? SCTP_AUTH_ACTIVE_KEY : SCTP_AUTH_DEACTIVATE_KEY,
			    &akid, sizeof(akid));
		}
		break;
	}
	case FUZZ_OP_HMAC_IDENT: {
		uint8_t habuf[sizeof(struct sctp_hmacalgo) + 4 * sizeof(uint16_t)];
		struct sctp_hmacalgo *ha = (struct sctp_hmacalgo *)(void *)habuf;
		uint16_t ids[4];
		uint8_t n, i;
		if (rd_u8(fc, &n)) {
			if (n > 4) {
				n = 4;
			}
			for (i = 0; i < n; i++) {
				if (!rd_u16(fc, &ids[i])) {
					n = 0;
					break;
				}
			}
			memset(habuf, 0, sizeof(habuf));
			ha->shmac_number_of_idents = n;
			for (i = 0; i < n; i++) {
				ha->shmac_idents[i] = ids[i];
			}
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_HMAC_IDENT, habuf, sizeof(struct sctp_hmacalgo) + (size_t)n * sizeof(uint16_t));
		}
		break;
	}
	case FUZZ_OP_SUPPORTED_TOGGLE: {
		struct sctp_assoc_value av;
		uint8_t which;
		uint32_t v;
		int opt;
		if (rd_u8(fc, &which) && rd_u32(fc, &v)) {
			static const int opts[7] = {
				SCTP_AUTH_SUPPORTED, SCTP_ASCONF_SUPPORTED,
				SCTP_RECONFIG_SUPPORTED, SCTP_NRSACK_SUPPORTED,
				SCTP_PKTDROP_SUPPORTED, SCTP_PR_SUPPORTED,
				SCTP_ECN_SUPPORTED
			};
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = v;
			opt = opts[which % 7];
			usrsctp_setsockopt(sock, IPPROTO_SCTP, opt, &av, sizeof(av));
		}
		break;
	}
	case FUZZ_OP_PEER_ADDR_PARAMS: {
		struct sctp_paddrparams pp;
		uint32_t hbinterval, flags, pathmtu;
		uint16_t pathmaxrxt;
		if (rd_u32(fc, &hbinterval) && rd_u16(fc, &pathmaxrxt) && rd_u32(fc, &flags) && rd_u32(fc, &pathmtu)) {
			memset(&pp, 0, sizeof(pp));
			fill_conn_addr((struct sockaddr_conn *)&pp.spp_address, 5001);
			pp.spp_assoc_id = assoc_id;
			pp.spp_hbinterval = hbinterval % 60001;
			pp.spp_pathmaxrxt = pathmaxrxt;
			pp.spp_flags = flags & (SPP_HB_ENABLE | SPP_HB_DISABLE | SPP_HB_DEMAND | SPP_PMTUD_ENABLE | SPP_PMTUD_DISABLE | SPP_HB_TIME_IS_ZERO);
			pp.spp_pathmtu = pathmtu % 9001;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &pp, sizeof(pp));
		}
		break;
	}
	case FUZZ_OP_UDP_ENCAPS: {
		struct sctp_udpencaps ue;
		uint16_t port;
		if (rd_u16(fc, &port)) {
			memset(&ue, 0, sizeof(ue));
			fill_conn_addr((struct sockaddr_conn *)&ue.sue_address, 5001);
			ue.sue_assoc_id = assoc_id;
			ue.sue_port = port;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &ue, sizeof(ue));
		}
		break;
	}
	case FUZZ_OP_MISC_U32: {
		struct sctp_assoc_value av;
		uint8_t which;
		uint32_t v;
		int opt;
		if (rd_u8(fc, &which) && rd_u32(fc, &v)) {
			static const int opts[6] = {
				SCTP_CONTEXT, SCTP_MAX_BURST, SCTP_EXPLICIT_EOR,
				SCTP_AUTO_ASCONF, SCTP_DISABLE_FRAGMENTS,
				SCTP_ACCEPT_ZERO_CHECKSUM
			};
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = v;
			opt = opts[which % 6];
			usrsctp_setsockopt(sock, IPPROTO_SCTP, opt, &av, sizeof(av));
		}
		break;
	}
	case FUZZ_OP_DEFAULT_SNDINFO: {
		struct sctp_sndinfo si;
		uint16_t sid, sndflags;
		uint32_t ppid, context;
		if (rd_u16(fc, &sid) && rd_u16(fc, &sndflags) && rd_u32(fc, &ppid) && rd_u32(fc, &context)) {
			memset(&si, 0, sizeof(si));
			si.snd_sid = sid;
			si.snd_flags = sndflags;
			si.snd_ppid = ppid;
			si.snd_context = context;
			si.snd_assoc_id = assoc_id;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_DEFAULT_SNDINFO, &si, sizeof(si));
		}
		break;
	}
	case FUZZ_OP_DEFAULT_PRINFO: {
		struct sctp_default_prinfo pi;
		uint16_t policy;
		uint32_t value;
		if (rd_u16(fc, &policy) && rd_u32(fc, &value)) {
			memset(&pi, 0, sizeof(pi));
			pi.pr_policy = policy % 4;
			pi.pr_value = value;
			pi.pr_assoc_id = assoc_id;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_DEFAULT_PRINFO, &pi, sizeof(pi));
		}
		break;
	}
	case FUZZ_OP_ENABLE_STREAM_RESET: {
		struct sctp_assoc_value av;
		uint32_t v;
		if (rd_u32(fc, &v)) {
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = v & 0x7;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av));
		}
		break;
	}
	case FUZZ_OP_INITMSG: {
		struct sctp_initmsg im;
		uint16_t ostreams, instreams, attempts, timeo;
		if (rd_u16(fc, &ostreams) && rd_u16(fc, &instreams) && rd_u16(fc, &attempts) && rd_u16(fc, &timeo)) {
			memset(&im, 0, sizeof(im));
			im.sinit_num_ostreams = ostreams;
			im.sinit_max_instreams = instreams;
			im.sinit_max_attempts = attempts;
			im.sinit_max_init_timeo = timeo;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &im, sizeof(im));
		}
		break;
	}
	case FUZZ_OP_CMT: {
		struct sctp_assoc_value av;
		uint32_t v, dac;
		if (rd_u32(fc, &v) && rd_u32(fc, &dac)) {
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = v % 5;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_CMT_ON_OFF, &av, sizeof(av));
			av.assoc_value = dac;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_CMT_USE_DAC, &av, sizeof(av));
		}
		break;
	}
	case FUZZ_OP_EVENT: {
		struct sctp_event event;
		uint16_t type;
		uint8_t on;
		if (rd_u16(fc, &type) && rd_u8(fc, &on)) {
			memset(&event, 0, sizeof(event));
			event.se_assoc_id = assoc_id;
			event.se_type = type;
			event.se_on = on & 1;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event));
		}
		break;
	}
	case FUZZ_OP_SYSCTL: {
		uint8_t which;
		uint32_t v;
		if (rd_u8(fc, &which) && rd_u32(fc, &v)) {
			switch (which % 8) {
			case 0: usrsctp_sysctl_set_sctp_heartbeat_interval_default(v % 60001); break;
			case 1: usrsctp_sysctl_set_sctp_delayed_sack_time_default(v % 501); break;
			case 2: usrsctp_sysctl_set_sctp_sack_freq_default(v % 6); break;
			case 3: usrsctp_sysctl_set_sctp_max_chunks_on_queue(v % 10001); break;
			case 4: usrsctp_sysctl_set_sctp_assoc_rtx_max_default(v % 101); break;
			case 5: usrsctp_sysctl_set_sctp_path_rtx_max_default(v % 101); break;
			case 6: usrsctp_sysctl_set_sctp_initial_cwnd(v % 101); break;
			case 7: usrsctp_sysctl_set_sctp_ootb_with_zero_cksum(v & 1); break;
			}
		}
		break;
	}
	case FUZZ_OP_ADD_STREAMS: {
		struct sctp_add_streams as;
		uint16_t instrms, outstrms;
		if (rd_u16(fc, &instrms) && rd_u16(fc, &outstrms)) {
			memset(&as, 0, sizeof(as));
			as.sas_assoc_id = assoc_id;
			as.sas_instrms = instrms % 129;
			as.sas_outstrms = outstrms % 129;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ADD_STREAMS, &as, sizeof(as));
		}
		break;
	}
	case FUZZ_OP_RESET_STREAMS: {
		uint8_t rsbuf[64];
		struct sctp_reset_streams *srs = (struct sctp_reset_streams *)rsbuf;
		uint16_t flags, n, i;
		uint16_t *list = (uint16_t *)(void *)srs->srs_stream_list;
		if (rd_u16(fc, &flags) && rd_u16(fc, &n)) {
			if (n > 4) {
				n = 4;
			}
			memset(rsbuf, 0, sizeof(rsbuf));
			srs->srs_assoc_id = assoc_id;
			srs->srs_flags = flags & (SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING);
			srs->srs_number_streams = n;
			for (i = 0; i < n; i++) {
				if (!rd_u16(fc, &list[i])) {
					break;
				}
			}
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs,
			    sizeof(struct sctp_reset_streams) + (size_t)n * sizeof(uint16_t));
		}
		break;
	}
	case FUZZ_OP_SET_PEER_PRIMARY: {
		struct sctp_setpeerprim sp;
		uint16_t port;
		if (rd_u16(fc, &port)) {
			memset(&sp, 0, sizeof(sp));
			fill_conn_addr((struct sockaddr_conn *)&sp.sspp_addr, 5001);
			sp.sspp_assoc_id = assoc_id;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_SET_PEER_PRIMARY_ADDR, &sp, sizeof(sp));
		}
		break;
	}
	case FUZZ_OP_INTERLEAVING: {
		struct sctp_assoc_value av;
		uint32_t v;
		if (rd_u32(fc, &v)) {
			memset(&av, 0, sizeof(av));
			av.assoc_id = assoc_id;
			av.assoc_value = v % 3;
			usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &av, sizeof(av));
			if (av.assoc_value == 2) {
				/* RFC 8260: interleaving needs fragment interleave 2 */
				av.assoc_value = 1;
				usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &av, sizeof(av));
			}
		}
		break;
	}
	default:
		break;
	}
}



static int
initialize_fuzzer(void)
{
	usrsctp_init(0, conn_output, NULL);

	usrsctp_enable_crc32c_offload();

#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

	usrsctp_register_address((void *)1);
	usrsctp_sysctl_set_sctp_pktdrop_enable(1);
	usrsctp_sysctl_set_sctp_nrsack_enable(1);

	fuzzer_printf("usrsctp initialized\n");
	return (1);
}

/* ---- getsockopt sweep ---- */

static void
apply_get_sweep(struct socket *sock, struct fuzz_cursor *fc)
{
	uint8_t id;
	sctp_assoc_t assoc_id = (sctp_assoc_t)SCTP_CURRENT_ASSOC;
	uint8_t buf[256];
	socklen_t len;

	if (!rd_u8(fc, &id)) {
		return;
	}

	switch (id) {
	case FUZZ_GET_STATUS: {
		struct sctp_status st;
		memset(&st, 0, sizeof(st));
		st.sstat_assoc_id = assoc_id;
		len = sizeof(st);
		usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_STATUS, &st, &len);
		break;
	}
	case FUZZ_GET_TIMEOUTS: {
		struct sctp_timeouts to;
		memset(&to, 0, sizeof(to));
		to.stimo_assoc_id = assoc_id;
		len = sizeof(to);
		usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_TIMEOUTS, &to, &len);
		break;
	}
	case FUZZ_GET_ASSOC_ID_LIST: {
		struct sctp_assoc_ids *ids = (struct sctp_assoc_ids *)(void *)buf;
		memset(buf, 0, sizeof(buf));
		ids->gaids_number_of_ids = 0;
		len = sizeof(buf);
		usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_GET_ASSOC_ID_LIST, buf, &len);
		break;
	}
	case FUZZ_GET_LOCAL_AUTH_CHUNKS:
	case FUZZ_GET_PEER_AUTH_CHUNKS: {
		struct sctp_authchunks *ac = (struct sctp_authchunks *)(void *)buf;
		memset(buf, 0, sizeof(buf));
		ac->gauth_assoc_id = assoc_id;
		len = sizeof(buf);
		usrsctp_getsockopt(sock, IPPROTO_SCTP,
		    (id == FUZZ_GET_LOCAL_AUTH_CHUNKS) ? SCTP_LOCAL_AUTH_CHUNKS : SCTP_PEER_AUTH_CHUNKS,
		    buf, &len);
		break;
	}
	case FUZZ_GET_SNDBUF_USE: {
		struct sctp_assoc_value av;
		memset(&av, 0, sizeof(av));
		av.assoc_id = assoc_id;
		len = sizeof(av);
		usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_GET_SNDBUF_USE, &av, &len);
		break;
	}
	case FUZZ_GET_PR_ASSOC_STATUS:
	case FUZZ_GET_PR_STREAM_STATUS: {
		struct sctp_prstatus ps;
		memset(&ps, 0, sizeof(ps));
		ps.sprstat_assoc_id = assoc_id;
		ps.sprstat_sid = 0;
		ps.sprstat_policy = 0;
		len = sizeof(ps);
		usrsctp_getsockopt(sock, IPPROTO_SCTP,
		    (id == FUZZ_GET_PR_ASSOC_STATUS) ? SCTP_PR_ASSOC_STATUS : SCTP_PR_STREAM_STATUS,
		    &ps, &len);
		break;
	}
	case FUZZ_GET_PEER_ADDR_INFO: {
		struct sctp_paddrinfo pi;
		memset(&pi, 0, sizeof(pi));
		fill_conn_addr((struct sockaddr_conn *)&pi.spinfo_address, 5001);
		pi.spinfo_assoc_id = assoc_id;
		len = sizeof(pi);
		usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_GET_PEER_ADDR_INFO, &pi, &len);
		break;
	}
	case FUZZ_GET_LOCAL_ADDR_SIZE:
	case FUZZ_GET_REMOTE_ADDR_SIZE: {
		int sz = 0;
		len = sizeof(sz);
		usrsctp_getsockopt(sock, IPPROTO_SCTP,
		    (id == FUZZ_GET_LOCAL_ADDR_SIZE) ? SCTP_GET_LOCAL_ADDR_SIZE : SCTP_GET_REMOTE_ADDR_SIZE,
		    &sz, &len);
		break;
	}
	default:
		break;
	}
}

/* ---- send phase: PR-SCTP / unordered / interleaved attacker parameters ---- */

static void
do_sends(struct socket *sock, struct fuzz_cursor *fc)
{
	uint8_t n_sends, i;

	if (!rd_u8(fc, &n_sends)) {
		return;
	}
	if (n_sends > FUZZ_MAX_SENDS) {
		n_sends = FUZZ_MAX_SENDS;
	}

	for (i = 0; i < n_sends; i++) {
		struct sctp_sendv_spa spa;
		uint16_t len, sid, sndflags, pr_policy, authkey;
		uint32_t ppid, context, pr_value;
		char *send_buffer;

		if (!rd_u16(fc, &len) || !rd_u16(fc, &sid) || !rd_u16(fc, &sndflags) ||
		    !rd_u32(fc, &ppid) || !rd_u32(fc, &context) || !rd_u16(fc, &pr_policy) ||
		    !rd_u32(fc, &pr_value) || !rd_u16(fc, &authkey)) {
			break;
		}
		if (len > FUZZ_MAX_SEND_LEN) {
			len = FUZZ_MAX_SEND_LEN;
		}
		send_buffer = malloc(len ? len : 1);
		if (send_buffer == NULL) {
			break;
		}
		memset(send_buffer, 0xab, len);

		memset(&spa, 0, sizeof(spa));
		spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
		spa.sendv_sndinfo.snd_sid = sid;
		spa.sendv_sndinfo.snd_flags = sndflags;
		spa.sendv_sndinfo.snd_ppid = ppid;
		spa.sendv_sndinfo.snd_context = context;
		spa.sendv_sndinfo.snd_assoc_id = (sctp_assoc_t)SCTP_CURRENT_ASSOC;
		if (pr_policy % 4) {
			spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
			spa.sendv_prinfo.pr_policy = pr_policy % 4;
			spa.sendv_prinfo.pr_value = pr_value;
		}
		if (authkey) {
			spa.sendv_flags |= SCTP_SEND_AUTHINFO_VALID;
			spa.sendv_authinfo.auth_keynumber = authkey % 8;
		}
		usrsctp_sendv(sock, send_buffer, len, NULL, 0, &spa, (socklen_t)sizeof(spa), SCTP_SENDV_SPA, 0);
		free(send_buffer);
	}
}



int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t data_size)
{
	static int initialized;
	struct fuzz_cursor fc;
	struct socket *socket_client;
	struct linger so_linger;
	struct sockaddr_conn sconn;
	struct sctp_common_header *common_header;
	uint8_t flags, n_pre, n_post, n_chunks, n_gets;
	uint8_t ticks[FUZZ_MAX_TICKS];
	uint8_t n_ticks = 0;
	uint8_t chunk_buffer[FUZZ_MAX_CHUNK_LEN];
	uint8_t pkt[COMMON_HEADER_SIZE + FUZZ_MAX_CHUNK_LEN];
	int result;
	int optval = 1;

	if (data_size < 2) {
		return (0);
	}
	if (!initialized) {
		initialized = initialize_fuzzer();
	}

	fc.data = data;
	fc.size = data_size;
	fc.pos = 0;
	memset(ticks, 0, sizeof(ticks));

	if (!rd_u8(&fc, &flags) || !rd_u8(&fc, &n_pre)) {
		return (0);
	}
	if (n_pre > FUZZ_MAX_OPTIONS) {
		n_pre = FUZZ_MAX_OPTIONS;
	}

	socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, 0);
	FUZZER_ASSERT(socket_client != NULL);

	usrsctp_set_non_blocking(socket_client, 1);

	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	result = usrsctp_setsockopt(socket_client, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger));
	FUZZER_ASSERT(result == 0);

	/* pre-connect option phase (INITMSG, CC/SS defaults, sysctls, ...) */
	while (n_pre-- > 0) {
		apply_option(socket_client, &fc, 0);
	}

	/* AUTH prelude: keys, protected chunks and HMAC preferences */
	if (flags & FUZZ_O_AUTH_PRELUDE) {
		uint8_t auth_prog[16];
		struct fuzz_cursor apc;
		auth_prog[0] = FUZZ_OP_AUTH_KEY;
		auth_prog[1] = 0x00; auth_prog[2] = 0x01; /* key id 1 */
		auth_prog[3] = 0x04;                      /* key length 4 */
		auth_prog[4] = 0x11; auth_prog[5] = 0x22; auth_prog[6] = 0x33; auth_prog[7] = 0x44;
		auth_prog[8] = FUZZ_OP_AUTH_CHUNK;
		auth_prog[9] = 0x00;                      /* protect DATA */
		auth_prog[10] = FUZZ_OP_HMAC_IDENT;
		auth_prog[11] = 0x02;                     /* 2 idents */
		auth_prog[12] = 0x00; auth_prog[13] = 0x01;
		auth_prog[14] = 0x00; auth_prog[15] = 0x03;
		apc.data = auth_prog;
		apc.size = sizeof(auth_prog);
		apc.pos = 0;
		apply_option(socket_client, &apc, 0);
	}

	fill_conn_addr(&sconn, 5000);
	result = usrsctp_bind(socket_client, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn));
	FUZZER_ASSERT(result == 0);

	/* Disable Nagle. */
	result = usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_NODELAY, &optval, sizeof(optval));
	FUZZER_ASSERT(result == 0);

	usrsctp_set_upcall(socket_client, handle_upcall, NULL);

	fill_conn_addr(&sconn, 5001);
	fuzzer_printf("Calling usrsctp_connect()\n");
	result = usrsctp_connect(socket_client, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn));
	FUZZER_ASSERT(result == 0 || errno == EINPROGRESS);

	/* establish the association with the recorded handshake */
	common_header = (struct sctp_common_header *)fuzz_init_ack;
	common_header->verification_tag = assoc_vtag;
	dump_packet(fuzz_init_ack, 448, SCTP_DUMP_INBOUND);
	usrsctp_conninput((void *)1, fuzz_init_ack, 448, 0);

	common_header = (struct sctp_common_header *)fuzz_cookie_ack;
	common_header->verification_tag = assoc_vtag;
	usrsctp_conninput((void *)1, fuzz_cookie_ack, 16, 0);

	/* timer phase 1: drive T3/heartbeat/sack timers deterministically */
	if (flags & FUZZ_O_TIMER_TICKS) {
		uint8_t i;
		if (rd_u8(&fc, &n_ticks)) {
			if (n_ticks > FUZZ_MAX_TICKS) {
				n_ticks = FUZZ_MAX_TICKS;
			}
			for (i = 0; i < n_ticks; i++) {
				if (!rd_u8(&fc, &ticks[i])) {
					n_ticks = i;
					break;
				}
				usrsctp_handle_timers((uint32_t)(ticks[i] % 201) * 10);
			}
		}
	}

	/* post-handshake option phase (assoc-scoped ops) */
	if (!rd_u8(&fc, &n_post)) {
		n_post = 0;
	}
	if (n_post > FUZZ_MAX_OPTIONS) {
		n_post = FUZZ_MAX_OPTIONS;
	}
	while (n_post-- > 0) {
		apply_option(socket_client, &fc, 1);
	}

	/* attacker packet transcript on the established association */
	if (!rd_u8(&fc, &n_chunks)) {
		n_chunks = 0;
	}
	if (n_chunks > FUZZ_MAX_CHUNKS) {
		n_chunks = FUZZ_MAX_CHUNKS;
	}
	while (n_chunks-- > 0) {
		uint8_t cflags;
		uint16_t len;
		if (!rd_u8(&fc, &cflags) || !rd_u16(&fc, &len)) {
			break;
		}
		if (len > FUZZ_MAX_CHUNK_LEN) {
			len = FUZZ_MAX_CHUNK_LEN;
		}
		if (len == 0) {
			break;
		}
		if (!rd_bytes(&fc, chunk_buffer, len)) {
			break;
		}
		if (cflags & 0x01) {
			/* optional send before the injection (incumbent semantics) */
			char sendbuf[2048];
			memset(sendbuf, 0x5a, sizeof(sendbuf));
			usrsctp_sendv(socket_client, sendbuf, sizeof(sendbuf), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
		}
		memcpy(pkt, fuzz_common_header, COMMON_HEADER_SIZE);
		memcpy(pkt + COMMON_HEADER_SIZE, chunk_buffer, len);
		common_header = (struct sctp_common_header *)pkt;
		/* inbound packets must carry our own tag (see fuzzer_connect.c) */
		common_header->verification_tag = assoc_vtag;
		usrsctp_conninput((void *)1, pkt, (size_t)len + COMMON_HEADER_SIZE, 0);
	}


	/* timer phase 2: let SACK/RTX timers observe the transcript */
	if (flags & FUZZ_O_TIMER_TICKS) {
		uint8_t i;
		for (i = 0; i < n_ticks; i++) {
			usrsctp_handle_timers((uint32_t)(ticks[i] % 201) * 10);
		}
	}

	do_sends(socket_client, &fc);

	/* timer phase 3: retransmissions, PR-SCTP abandonment, autoclose */
	if (flags & FUZZ_O_TIMER_TICKS) {
		uint8_t i;
		for (i = 0; i < n_ticks; i++) {
			usrsctp_handle_timers((uint32_t)(ticks[i] % 201) * 10);
		}
	}

	if (!rd_u8(&fc, &n_gets)) {
		n_gets = 0;
	}
	if (n_gets > FUZZ_MAX_GETS) {
		n_gets = FUZZ_MAX_GETS;
	}
	while (n_gets-- > 0) {
		apply_get_sweep(socket_client, &fc);
	}

	/* peel the association off onto its own socket */
	if (flags & FUZZ_O_PEEL_OFF) {
		uint8_t assoc_id_buf[64];
		struct sctp_assoc_ids *ids = (struct sctp_assoc_ids *)(void *)assoc_id_buf;
		struct sctp_recvv_rn rn;
		socklen_t id_len = sizeof(assoc_id_buf);

		memset(assoc_id_buf, 0, sizeof(assoc_id_buf));
		ids->gaids_number_of_ids = 15;
		if (usrsctp_getsockopt(socket_client, IPPROTO_SCTP, SCTP_GET_ASSOC_ID_LIST, assoc_id_buf, &id_len) == 0 &&
		    ids->gaids_number_of_ids > 0) {
			struct socket *peeled_socket = usrsctp_peeloff(socket_client, ids->gaids_assoc_id[0]);
			if (peeled_socket != NULL) {
				struct sockaddr_in addr;
				char rbuf[BUFFER_SIZE];
				int rflags = 0;
				socklen_t rlen = (socklen_t)sizeof(struct sockaddr_in);
				unsigned int infotype = 0;
				socklen_t infolen = sizeof(struct sctp_recvv_rn);
				memset(&rn, 0, sizeof(rn));
				(void)usrsctp_recvv(peeled_socket, rbuf, sizeof(rbuf), (struct sockaddr *)&addr, &rlen, (void *)&rn, &infolen, &infotype, &rflags);
				usrsctp_close(peeled_socket);
			}
		}
	}

	/* peer-initiated graceful shutdown */
	if (flags & FUZZ_O_PEER_SHUTDOWN) {
		uint8_t sbuf[COMMON_HEADER_SIZE + 8];
		memcpy(sbuf, fuzz_common_header, COMMON_HEADER_SIZE);
		memcpy(sbuf + COMMON_HEADER_SIZE, fuzz_shutdown_chunk, 8);
		common_header = (struct sctp_common_header *)sbuf;
		common_header->verification_tag = assoc_vtag;
		usrsctp_conninput((void *)1, sbuf, sizeof(sbuf), 0);

		memcpy(sbuf, fuzz_common_header, COMMON_HEADER_SIZE);
		memcpy(sbuf + COMMON_HEADER_SIZE, fuzz_shutdown_ack_chunk, 4);
		common_header = (struct sctp_common_header *)sbuf;
		common_header->verification_tag = assoc_vtag;
		usrsctp_conninput((void *)1, sbuf, COMMON_HEADER_SIZE + 4, 0);

		memcpy(sbuf, fuzz_common_header, COMMON_HEADER_SIZE);
		memcpy(sbuf + COMMON_HEADER_SIZE, fuzz_shutdown_complete_chunk, 8);
		common_header = (struct sctp_common_header *)sbuf;
		common_header->verification_tag = assoc_vtag;
		usrsctp_conninput((void *)1, sbuf, sizeof(sbuf), 0);
	}

	/* local graceful shutdown */
	if (flags & FUZZ_O_LOCAL_SHUTDOWN) {
		uint8_t sbuf[COMMON_HEADER_SIZE + 4];
		usrsctp_shutdown(socket_client, 1 /* SHUT_WR */);
		memcpy(sbuf, fuzz_common_header, COMMON_HEADER_SIZE);
		memcpy(sbuf + COMMON_HEADER_SIZE, fuzz_shutdown_ack_chunk, 4);
		common_header = (struct sctp_common_header *)sbuf;
		common_header->verification_tag = assoc_vtag;
		usrsctp_conninput((void *)1, sbuf, COMMON_HEADER_SIZE + 4, 0);
	}

	fuzzer_printf("Calling usrsctp_close()\n");
	usrsctp_close(socket_client);

	return (0);
}

