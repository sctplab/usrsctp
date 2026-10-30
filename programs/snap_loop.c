/*
 * Copyright (C) 2026 Espressif Systems
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
 * Exercises SNAP, the SCTP Negotiation Acceleration Protocol
 * (draft-uberti-tsvwg-warp, section 4.1): two AF_CONN endpoints in one process
 * swap their INIT chunks out-of-band instead of running the SCTP handshake.
 * Packets travel through in-process queues, so the program also sees which
 * chunks reach the "wire".
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <usrsctp.h>

#define PORT 5000
#define MAX_PACKETS 64
#define MAX_PACKET_SIZE 2048
#define INIT_BUF_SIZE 1024

struct packet {
	size_t len;
	uint8_t data[MAX_PACKET_SIZE];
};

struct endpoint {
	struct socket *sock;
	struct endpoint *peer;
	/* Packets this endpoint sent, waiting for delivery to the peer. */
	struct packet *queue;
	int queued;
	/* INIT, INIT-ACK, COOKIE-ECHO and COOKIE-ACK chunks it sent. */
	int handshake_chunks;
	int comm_up;
	char received[64];
};

#ifdef _WIN32
static CRITICAL_SECTION lock;
#else
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
#endif
static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static void
lock_queues(void)
{
#ifdef _WIN32
	EnterCriticalSection(&lock);
#else
	pthread_mutex_lock(&lock);
#endif
}

static void
unlock_queues(void)
{
#ifdef _WIN32
	LeaveCriticalSection(&lock);
#else
	pthread_mutex_unlock(&lock);
#endif
}

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	struct endpoint *ep = addr;
	const uint8_t *p = buf;
	size_t offset = 12;

	(void)tos;
	(void)set_df;
	lock_queues();
	if (length <= MAX_PACKET_SIZE && ep->queued < MAX_PACKETS) {
		memcpy(ep->queue[ep->queued].data, buf, length);
		ep->queue[ep->queued].len = length;
		ep->queued++;
	}
	/* Walk the chunks after the 12 byte common header. */
	while (offset + 4 <= length) {
		uint16_t chunk_len = (uint16_t)(p[offset + 2] << 8 | p[offset + 3]);

		if (p[offset] == 1 || p[offset] == 2 || p[offset] == 10 || p[offset] == 11) {
			ep->handshake_chunks++;
		}
		if (chunk_len < 4) {
			break;
		}
		offset += (chunk_len + 3u) & ~3u;
	}
	unlock_queues();
	return (0);
}

static int
receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	struct endpoint *ep = ulp_info;
	union sctp_notification *notif;

	(void)sock;
	(void)addr;
	(void)rcv;
	if (data == NULL) {
		return (1);
	}
	if (flags & MSG_NOTIFICATION) {
		notif = data;
		if (notif->sn_header.sn_type == SCTP_ASSOC_CHANGE &&
		    notif->sn_assoc_change.sac_state == SCTP_COMM_UP) {
			ep->comm_up++;
		}
	} else if (datalen < sizeof(ep->received)) {
		memcpy(ep->received, data, datalen);
		ep->received[datalen] = '\0';
	}
	free(data);
	return (1);
}

/* Delivers queued packets until both directions are quiet. */
static void
pump(struct endpoint *a, struct endpoint *b)
{
	struct endpoint *eps[2] = {a, b};
	struct packet pkt;
	int i, moved;

	do {
		moved = 0;
		for (i = 0; i < 2; i++) {
			lock_queues();
			if (eps[i]->queued == 0) {
				unlock_queues();
				continue;
			}
			pkt = eps[i]->queue[0];
			memmove(&eps[i]->queue[0], &eps[i]->queue[1], sizeof(struct packet) * (size_t)(eps[i]->queued - 1));
			eps[i]->queued--;
			unlock_queues();
			usrsctp_conninput(eps[i]->peer, pkt.data, pkt.len, 0);
			moved = 1;
		}
	} while (moved);
}

static struct sockaddr_conn
conn_addr(struct endpoint *ep)
{
	struct sockaddr_conn sconn;

	memset(&sconn, 0, sizeof(sconn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(sconn);
#endif
	sconn.sconn_port = htons(PORT);
	/* With AF_CONN the address names the local transport. */
	sconn.sconn_addr = ep;
	return (sconn);
}

static void
setup(struct endpoint *ep, struct endpoint *peer)
{
	struct sockaddr_conn sconn = conn_addr(ep);
	struct sctp_event event;
	struct linger linger_opt;
	const int on = 1;

	memset(ep, 0, sizeof(*ep));
	ep->peer = peer;
	ep->queue = calloc(MAX_PACKETS, sizeof(struct packet));
	usrsctp_register_address(ep);
	ep->sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, ep);
	if (ep->sock == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	usrsctp_set_non_blocking(ep->sock, 1);
	(void)usrsctp_setsockopt(ep->sock, IPPROTO_SCTP, SCTP_NODELAY, &on, sizeof(on));
	/* Abort on close, so the next case can bind the port again. */
	linger_opt.l_onoff = 1;
	linger_opt.l_linger = 0;
	(void)usrsctp_setsockopt(ep->sock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	event.se_type = SCTP_ASSOC_CHANGE;
	(void)usrsctp_setsockopt(ep->sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event));
	if (usrsctp_bind(ep->sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
}

static void
teardown(struct endpoint *ep)
{
	usrsctp_close(ep->sock);
	usrsctp_deregister_address(ep);
	free(ep->queue);
}

/* The INIT chunk to hand to the peer out-of-band, e.g. in the SDP. */
static int
prepare(struct endpoint *ep, uint8_t *init, size_t *init_len)
{
	struct sockaddr_conn sconn = conn_addr(ep);

	*init_len = INIT_BUF_SIZE;
	return (usrsctp_snap_prepare(ep->sock, (struct sockaddr *)&sconn, sizeof(sconn), init, init_len));
}

static void
send_text(struct endpoint *ep, const char *text)
{
	struct sctp_sndinfo sndinfo;

	memset(&sndinfo, 0, sizeof(sndinfo));
	sndinfo.snd_sid = 1;
	sndinfo.snd_ppid = htonl(51);
	CHECK(usrsctp_sendv(ep->sock, text, strlen(text), NULL, 0, &sndinfo,
	                    (socklen_t)sizeof(sndinfo), SCTP_SENDV_SNDINFO, 0) > 0);
}

static void
test_snap(void)
{
	struct endpoint a, b;
	uint8_t init_a[INIT_BUF_SIZE], init_b[INIT_BUF_SIZE];
	size_t len_a, len_b;

	printf("snap: both sides open from the peer's INIT, without the handshake\n");
	setup(&a, &b);
	setup(&b, &a);
	CHECK(prepare(&a, init_a, &len_a) == 0);
	CHECK(prepare(&b, init_b, &len_b) == 0);
	/* Data sent before the open waits, as a DCEP OPEN would. */
	send_text(&a, "hello");
	/* Once the lower layer (DTLS) is up, each side applies the other's INIT. */
	CHECK(usrsctp_snap_establish(a.sock, init_b, len_b, 0) == 0);
	CHECK(usrsctp_snap_establish(b.sock, init_a, len_a, 0) == 0);
	CHECK(a.comm_up == 1 && b.comm_up == 1);
	pump(&a, &b);
	CHECK(strcmp(b.received, "hello") == 0);
	send_text(&b, "world");
	pump(&a, &b);
	CHECK(strcmp(a.received, "world") == 0);
	CHECK(a.handshake_chunks == 0 && b.handshake_chunks == 0);
	teardown(&a);
	teardown(&b);
}

static void
test_fallback(void)
{
	struct endpoint a, b;
	struct sockaddr_conn sconn;
	uint8_t init_a[INIT_BUF_SIZE];
	size_t len_a;

	printf("fallback: a prepared side opens with the handshake against a peer without SNAP\n");
	setup(&a, &b);
	setup(&b, &a);
	CHECK(prepare(&a, init_a, &len_a) == 0);
	send_text(&a, "hello");
	sconn = conn_addr(&b);
	CHECK(usrsctp_connect(b.sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0 && errno == EINPROGRESS);
	CHECK(usrsctp_snap_send_init(a.sock) == 0);
	pump(&a, &b);
	CHECK(a.comm_up == 1 && b.comm_up == 1);
	CHECK(strcmp(b.received, "hello") == 0);
	teardown(&a);
	teardown(&b);
}

static void
test_invalid(void)
{
	struct endpoint a, b;
	uint8_t init_a[INIT_BUF_SIZE], init_b[INIT_BUF_SIZE], bad[INIT_BUF_SIZE];
	size_t len_a, len_b;

	printf("invalid: a malformed INIT is refused, and the association stays prepared\n");
	setup(&a, &b);
	setup(&b, &a);
	CHECK(prepare(&a, init_a, &len_a) == 0);
	CHECK(prepare(&b, init_b, &len_b) == 0);
	memcpy(bad, init_b, len_b);
	memset(bad + 4, 0, 4); /* initiate tag 0 */
	errno = 0;
	CHECK(usrsctp_snap_establish(a.sock, bad, len_b, 0) < 0 && errno == EINVAL);
	CHECK(usrsctp_snap_establish(a.sock, init_b, len_b, 0) == 0);
	CHECK(a.comm_up == 1);
	teardown(&a);
	teardown(&b);
}

int
main(void)
{
#ifdef _WIN32
	InitializeCriticalSection(&lock);
#endif
	usrsctp_init(0, conn_output, NULL);
	test_snap();
	test_fallback();
	test_invalid();
	while (usrsctp_finish() != 0) {
#ifdef _WIN32
		Sleep(100);
#else
		usleep(100000);
#endif
	}
	if (failures != 0) {
		printf("%d check(s) failed\n", failures);
		return (EXIT_FAILURE);
	}
	printf("all passed\n");
	return (EXIT_SUCCESS);
}
