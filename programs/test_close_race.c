/*
 * Copyright (C) 2026 Apple Inc.
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
 * Closes sockets while another thread is processing their associations.
 *
 * Packet input and the timer handler take a reference on the socket for the
 * upcall. usrsctp_close() could release the last reference while they were
 * doing so, or, when closing a listening socket, abort a connection not
 * accepted yet on which the timer handler had taken one: the socket was then
 * freed twice, or used after it had been freed. See sctplab/usrsctp#676 and
 * sctplab/usrsctp#709.
 *
 * Three modes:
 * - input: the peer's ABORT is passed to usrsctp_conninput() on one thread
 *   while usrsctp_close() runs on another. This is how WebRTC data channels
 *   close: both peers close with SO_LINGER 0, so the peer's ABORT can arrive
 *   while the local socket is being closed.
 * - timer: the socket has unacknowledged data and a retransmission timer
 *   firing every tick, and the main thread closes it at a varying offset
 *   while the timer thread handles the timeouts.
 * - listen: connections which have not been accepted have heartbeat timers
 *   firing every tick while the main thread closes the listening socket,
 *   which aborts them.
 *
 * Each iteration sets up new associations over AF_CONN and varies the timing.
 * The program does not detect a double free or a use-after-free itself: build
 * usrsctp with -Dsctp_invariants=ON, which catches them in every mode, or with
 * AddressSanitizer, which may miss them in input mode. It also fails if
 * usrsctp_finish() does not complete, which means something was leaked.
 *
 * Usage: test_close_race [iterations] [input|timer|listen]
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <usrsctp.h>
#include "programs_helper.h"

#define MAX_PACKETS 1024
#define MAX_PACKET_SIZE 2048
#define SCTP_CHUNK_TYPE_ABORT 6
#define DELAY_STEPS 64
#define BASE_PORT 5000
#define MAX_ITERATIONS 60000 /* BASE_PORT + MAX_ITERATIONS must fit in a port number */
#define LISTEN_CLIENTS 16
#define FINISH_TIMEOUT_MS 30000

enum mode { MODE_INPUT, MODE_TIMER, MODE_LISTEN };

struct packet {
	size_t length;
	char data[MAX_PACKET_SIZE];
};

struct endpoint {
	struct socket *sock;
	struct endpoint *peer;
	pthread_mutex_t mutex;
	struct packet queue[MAX_PACKETS]; /* packets to be delivered to this endpoint */
	int count;
};

static struct endpoint endpoint_a, endpoint_b;
static struct packet abort_packet;
static atomic_int arrived;
static unsigned int abort_delay, close_delay;

/* Each endpoint uses its own address for both ends, so addr is the sender */
static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	struct endpoint *to = ((struct endpoint *)addr)->peer;

	(void)tos;
	(void)set_df;
	pthread_mutex_lock(&to->mutex);
	if (to->count < MAX_PACKETS && length <= MAX_PACKET_SIZE) {
		memcpy(to->queue[to->count].data, buf, length);
		to->queue[to->count].length = length;
		to->count++;
	}
	pthread_mutex_unlock(&to->mutex);
	return (0);
}

static int
pop_packet(struct endpoint *ep, struct packet *packet)
{
	int ret = 0;

	pthread_mutex_lock(&ep->mutex);
	if (ep->count > 0) {
		*packet = ep->queue[0];
		memmove(ep->queue, ep->queue + 1, (ep->count - 1) * sizeof(struct packet));
		ep->count--;
		ret = 1;
	}
	pthread_mutex_unlock(&ep->mutex);
	return (ret);
}

static int
deliver(struct endpoint *ep)
{
	struct packet packet;
	int n = 0;

	while (pop_packet(ep, &packet)) {
		usrsctp_conninput(ep, packet.data, packet.length, 0);
		n++;
	}
	return (n);
}

static void
discard(struct endpoint *ep)
{
	pthread_mutex_lock(&ep->mutex);
	ep->count = 0;
	pthread_mutex_unlock(&ep->mutex);
}

/* Binds to port on ep, and connects to remote_port on ep unless it is 0 */
static struct socket *
open_socket(struct endpoint *ep, uint16_t port, uint16_t remote_port)
{
	struct socket *sock;
	struct sockaddr_conn sconn;
	struct linger linger;

	if ((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	usrsctp_set_non_blocking(sock, 1);
	linger.l_onoff = 1;
	linger.l_linger = 0;
	usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	memset(&sconn, 0, sizeof(sconn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(sconn);
#endif
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = ep;
	if (usrsctp_bind(sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
	if (remote_port != 0) {
		sconn.sconn_port = htons(remote_port);
		if (usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0 &&
		    errno != EINPROGRESS) {
			perror("usrsctp_connect");
			exit(EXIT_FAILURE);
		}
	}
	return (sock);
}

static int
established(struct socket *sock)
{
	struct sctp_status status;
	socklen_t len = (socklen_t)sizeof(status);

	if (usrsctp_getsockopt(sock, IPPROTO_SCTP, SCTP_STATUS, &status, &len) < 0) {
		return (0);
	}
	return (status.sstat_state == SCTP_ESTABLISHED);
}

static int
send_message(struct socket *sock)
{
	char message[1000];
	struct sctp_sndinfo sndinfo;

	memset(message, 'x', sizeof(message));
	memset(&sndinfo, 0, sizeof(sndinfo));
	if (usrsctp_sendv(sock, message, sizeof(message), NULL, 0, &sndinfo, (socklen_t)sizeof(sndinfo),
	    SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("usrsctp_sendv");
		return (-1);
	}
	return (0);
}

static void
spin(unsigned int n)
{
	volatile unsigned int i;

	for (i = 0; i < n * 16; i++)
		;
}

static void
barrier(void)
{
	atomic_fetch_add(&arrived, 1);
	while (atomic_load(&arrived) < 2)
		;
}

static void *
abort_thread(void *arg)
{
	(void)arg;
	barrier();
	spin(abort_delay);
	usrsctp_conninput(&endpoint_b, abort_packet.data, abort_packet.length, 0);
	return (NULL);
}

static void *
close_thread(void *arg)
{
	(void)arg;
	barrier();
	spin(close_delay);
	usrsctp_close(endpoint_b.sock);
	return (NULL);
}

static int
run_pair(unsigned int i, enum mode mode)
{
	pthread_t t1, t2;
	struct packet packet;
	int round, found, rc;

	discard(&endpoint_a);
	discard(&endpoint_b);
	endpoint_a.sock = open_socket(&endpoint_a, (uint16_t)(BASE_PORT + i), (uint16_t)(BASE_PORT + i));
	endpoint_b.sock = open_socket(&endpoint_b, (uint16_t)(BASE_PORT + i), (uint16_t)(BASE_PORT + i));
	for (round = 0; round < 1000; round++) {
		if (deliver(&endpoint_a) + deliver(&endpoint_b) == 0) {
			if (established(endpoint_a.sock) && established(endpoint_b.sock)) {
				break;
			}
			usleep(1000);
		}
	}
	if (!established(endpoint_a.sock) || !established(endpoint_b.sock)) {
		fprintf(stderr, "Iteration %u: association not established\n", i);
		return (-1);
	}

	if (mode == MODE_TIMER) {
		/*
		 * Nothing is delivered from now on, so the data is never
		 * acknowledged and the retransmission timer keeps firing.
		 */
		if (send_message(endpoint_b.sock) < 0) {
			return (-1);
		}
		/* Timer ticks are 10 ms: close at an offset that cycles through 15 to 35 ms */
		usleep(15000 + (i * 317) % 20000);
		usrsctp_close(endpoint_b.sock);
		usrsctp_close(endpoint_a.sock);
		return (0);
	}

	/* The peer closes first: keep its ABORT for the race */
	usrsctp_close(endpoint_a.sock);
	found = 0;
	while (pop_packet(&endpoint_b, &packet)) {
		if (packet.length > 12 && (uint8_t)packet.data[12] == SCTP_CHUNK_TYPE_ABORT) {
			abort_packet = packet;
			found = 1;
		}
	}
	if (!found) {
		fprintf(stderr, "Iteration %u: no ABORT from the peer\n", i);
		return (-1);
	}

	/* Delay either side, by 0 to DELAY_STEPS - 1 */
	abort_delay = (i % 2) ? (i / 2) % DELAY_STEPS : 0;
	close_delay = (i % 2) ? 0 : (i / 2) % DELAY_STEPS;
	atomic_store(&arrived, 0);
	if ((rc = pthread_create(&t1, NULL, abort_thread, NULL)) != 0 ||
	    (rc = pthread_create(&t2, NULL, close_thread, NULL)) != 0) {
		/* A thread may already wait for the other at the barrier */
		fprintf(stderr, "Iteration %u: pthread_create: %s\n", i, strerror(rc));
		exit(EXIT_FAILURE);
	}
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	return (0);
}

static int
run_listen(unsigned int i)
{
	struct socket *clients[LISTEN_CLIENTS];
	int k, round;
	uint16_t port = (uint16_t)(BASE_PORT + i);

	discard(&endpoint_a);
	discard(&endpoint_b);
	endpoint_b.sock = open_socket(&endpoint_b, port, 0);
	if (usrsctp_listen(endpoint_b.sock, LISTEN_CLIENTS) < 0) {
		perror("usrsctp_listen");
		return (-1);
	}
	for (k = 0; k < LISTEN_CLIENTS; k++) {
		clients[k] = open_socket(&endpoint_a, 0, port);
	}
	/* Heartbeats start as soon as an association is up, so don't wait for silence */
	for (round = 0; round < 10000; round++) {
		deliver(&endpoint_a);
		deliver(&endpoint_b);
		for (k = 0; k < LISTEN_CLIENTS && established(clients[k]); k++)
			;
		if (k == LISTEN_CLIENTS) {
			break;
		}
		usleep(1000);
	}
	if (k < LISTEN_CLIENTS) {
		fprintf(stderr, "Iteration %u: association %d not established\n", i, k);
		return (-1);
	}

	/*
	 * The connections are never accepted, and nothing is delivered from
	 * now on, so their heartbeats are never answered. Timer ticks are
	 * 10 ms: close at an offset that cycles through 15 to 35 ms.
	 */
	usleep(15000 + (i * 317) % 20000);
	usrsctp_close(endpoint_b.sock);
	for (k = 0; k < LISTEN_CLIENTS; k++) {
		usrsctp_close(clients[k]);
	}
	return (0);
}

static void
usage(const char *name)
{
	fprintf(stderr, "Usage: %s [iterations (1 to %d)] [input|timer|listen]\n", name, MAX_ITERATIONS);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	unsigned int i, iterations = 2000;
	enum mode mode = MODE_INPUT;
	const char *mode_name = "input";
	char *end;
	int ms, rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 3) {
		usage(argv[0]);
	}
	if (argc > 1) {
		unsigned long value = strtoul(argv[1], &end, 10);

		if (*argv[1] == '\0' || *end != '\0' || value == 0 || value > MAX_ITERATIONS) {
			usage(argv[0]);
		}
		iterations = (unsigned int)value;
	}
	if (argc > 2) {
		mode_name = argv[2];
		if (strcmp(mode_name, "input") == 0) {
			mode = MODE_INPUT;
		} else if (strcmp(mode_name, "timer") == 0) {
			mode = MODE_TIMER;
		} else if (strcmp(mode_name, "listen") == 0) {
			mode = MODE_LISTEN;
		} else {
			usage(argv[0]);
		}
	}

	endpoint_a.peer = &endpoint_b;
	endpoint_b.peer = &endpoint_a;
	if ((rc = pthread_mutex_init(&endpoint_a.mutex, NULL)) != 0 ||
	    (rc = pthread_mutex_init(&endpoint_b.mutex, NULL)) != 0) {
		fprintf(stderr, "pthread_mutex_init: %s\n", strerror(rc));
		return (EXIT_FAILURE);
	}

	usrsctp_init(0, conn_output, debug_printf_stack);
	usrsctp_sysctl_set_sctp_ecn_enable(0);
	/* Retransmit every tick, and do not give up while waiting or before the socket is closed */
	usrsctp_sysctl_set_sctp_rto_min_default(10);
	usrsctp_sysctl_set_sctp_rto_max_default(10);
	usrsctp_sysctl_set_sctp_rto_initial_default(10);
	usrsctp_sysctl_set_sctp_init_rtx_max_default(1000);
	usrsctp_sysctl_set_sctp_assoc_rtx_max_default(100);
	usrsctp_sysctl_set_sctp_path_rtx_max_default(100);
	if (mode == MODE_LISTEN) {
		/* Send heartbeats about every tick */
		usrsctp_sysctl_set_sctp_heartbeat_interval_default(1);
	}
	usrsctp_register_address(&endpoint_a);
	usrsctp_register_address(&endpoint_b);

	for (i = 0; i < iterations; i++) {
		if ((mode == MODE_LISTEN ? run_listen(i) : run_pair(i, mode)) < 0) {
			return (EXIT_FAILURE);
		}
	}
	printf("%u iterations done (%s mode)\n", iterations, mode_name);

	usrsctp_deregister_address(&endpoint_a);
	usrsctp_deregister_address(&endpoint_b);
	for (ms = 0; usrsctp_finish() != 0; ms += 100) {
		if (ms >= FINISH_TIMEOUT_MS) {
			fprintf(stderr, "usrsctp_finish() did not complete, something was leaked\n");
			return (EXIT_FAILURE);
		}
		usleep(100000);
	}
	return (EXIT_SUCCESS);
}
