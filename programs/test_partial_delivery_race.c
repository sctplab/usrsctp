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
 * Reads partially delivered messages while their last fragment is added.
 *
 * A message larger than the partial delivery point is put on the read queue
 * before it is complete, and its other fragments are added to it as they
 * arrive. Packet input added the last fragment, unlocked the read queue and
 * then used the message again, while the reader could already have read it
 * and freed it.
 *
 * One thread passes the packets to usrsctp_conninput() while another polls
 * usrsctp_recvv() on a non-blocking socket, so that it reads each message as
 * soon as data is available. Every message is larger than the partial
 * delivery point, and the reader checks its size and content. Unordered
 * messages still arrive in order, since no packet is lost.
 *
 * The program does not detect a use-after-free itself: build usrsctp with
 * AddressSanitizer, which catches it in both modes, or with
 * -Dsctp_invariants=ON, which panics in ordered mode when the receive window
 * accounting goes wrong. It also fails if the reader makes no progress for a
 * while, or if usrsctp_finish() does not complete, which means something was
 * leaked.
 *
 * Usage: test_partial_delivery_race [messages] [ordered|unordered]
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <usrsctp.h>
#include "programs_helper.h"

#define MAX_PACKETS 1024
#define MAX_PACKET_SIZE 2048
#define PORT 5000
#define MESSAGE_SIZE 8192
#define PARTIAL_DELIVERY_POINT 1024
#define MAX_MESSAGES 10000000
#define STALL_TIMEOUT_S 30
#define FINISH_TIMEOUT_MS 30000

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
static atomic_int stop;
static unsigned int messages = 20000;

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

static void *
input_thread(void *arg)
{
	(void)arg;
	while (!atomic_load(&stop)) {
		if (deliver(&endpoint_a) + deliver(&endpoint_b) == 0) {
			sched_yield();
		}
	}
	return (NULL);
}

/* Binds to the port on ep and connects to the same port on its peer */
static struct socket *
open_socket(struct endpoint *ep)
{
	struct socket *sock;
	struct sockaddr_conn sconn;
	struct linger linger;
	int level = 0;

	if ((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
		exit(EXIT_FAILURE);
	}
	usrsctp_set_non_blocking(sock, 1);
	/* The input thread is stopped before the sockets are closed: abort instead of shutting down */
	linger.l_onoff = 1;
	linger.l_linger = 0;
	usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	/* Deliver one message at a time, like WebRTC data channels */
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &level, sizeof(level)) < 0) {
		perror("SCTP_FRAGMENT_INTERLEAVE");
		exit(EXIT_FAILURE);
	}
	memset(&sconn, 0, sizeof(sconn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(sconn);
#endif
	sconn.sconn_port = htons(PORT);
	sconn.sconn_addr = ep;
	if (usrsctp_bind(sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
	if (usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof(sconn)) < 0 &&
	    errno != EINPROGRESS) {
		perror("usrsctp_connect");
		exit(EXIT_FAILURE);
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

static unsigned char
pattern(unsigned int message, size_t offset)
{
	return ((unsigned char)(message * 131 + offset * 7 + offset / 251));
}

static void *
receive_thread(void *arg)
{
	unsigned char message[MESSAGE_SIZE], buffer[4096];
	struct sockaddr_conn from;
	struct sctp_rcvinfo rcvinfo;
	socklen_t fromlen, infolen;
	unsigned int infotype, received = 0;
	size_t length = 0, i;
	time_t progress = time(NULL);
	ssize_t n;
	int flags;

	(void)arg;
	while (received < messages) {
		fromlen = (socklen_t)sizeof(from);
		infolen = (socklen_t)sizeof(rcvinfo);
		infotype = 0;
		flags = 0;
		n = usrsctp_recvv(endpoint_b.sock, buffer, sizeof(buffer), (struct sockaddr *)&from,
		    &fromlen, &rcvinfo, &infolen, &infotype, &flags);
		if (n < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				if (time(NULL) - progress > STALL_TIMEOUT_S) {
					fprintf(stderr, "Message %u: nothing received for %d seconds\n",
					    received, STALL_TIMEOUT_S);
					exit(EXIT_FAILURE);
				}
				continue;
			}
			perror("usrsctp_recvv");
			exit(EXIT_FAILURE);
		}
		if (n == 0) {
			fprintf(stderr, "Message %u: connection closed\n", received);
			exit(EXIT_FAILURE);
		}
		if (length + (size_t)n > sizeof(message)) {
			fprintf(stderr, "Message %u: %zu bytes without end of record\n",
			    received, length + (size_t)n);
			exit(EXIT_FAILURE);
		}
		memcpy(message + length, buffer, (size_t)n);
		length += (size_t)n;
		progress = time(NULL);
		if ((flags & MSG_EOR) == 0) {
			continue;
		}
		if (length != sizeof(message)) {
			fprintf(stderr, "Message %u: %zu bytes, expected %zu\n", received, length, sizeof(message));
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < length; i++) {
			if (message[i] != pattern(received, i)) {
				fprintf(stderr, "Message %u: wrong data at offset %zu\n", received, i);
				exit(EXIT_FAILURE);
			}
		}
		received++;
		length = 0;
	}
	return (NULL);
}

static void
send_messages(int unordered)
{
	unsigned char message[MESSAGE_SIZE];
	struct sctp_sndinfo sndinfo;
	unsigned int i;
	size_t j;

	memset(&sndinfo, 0, sizeof(sndinfo));
	if (unordered) {
		sndinfo.snd_flags = SCTP_UNORDERED;
	}
	for (i = 0; i < messages; i++) {
		for (j = 0; j < sizeof(message); j++) {
			message[j] = pattern(i, j);
		}
		while (usrsctp_sendv(endpoint_a.sock, message, sizeof(message), NULL, 0, &sndinfo,
		    (socklen_t)sizeof(sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
			if (errno != EWOULDBLOCK && errno != EAGAIN) {
				perror("usrsctp_sendv");
				exit(EXIT_FAILURE);
			}
			sched_yield();
		}
	}
}

static void
usage(const char *name)
{
	fprintf(stderr, "Usage: %s [messages (1 to %d)] [ordered|unordered]\n", name, MAX_MESSAGES);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	pthread_t input, receive;
	uint32_t point = PARTIAL_DELIVERY_POINT;
	const char *mode_name = "ordered";
	int round, ms, rc, unordered = 0;
	unsigned long value;
	char *end;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 3) {
		usage(argv[0]);
	}
	if (argc > 1) {
		value = strtoul(argv[1], &end, 10);
		if (*argv[1] == '\0' || *end != '\0' || value == 0 || value > MAX_MESSAGES) {
			usage(argv[0]);
		}
		messages = (unsigned int)value;
	}
	if (argc > 2) {
		mode_name = argv[2];
		if (strcmp(mode_name, "unordered") == 0) {
			unordered = 1;
		} else if (strcmp(mode_name, "ordered") != 0) {
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
	usrsctp_register_address(&endpoint_a);
	usrsctp_register_address(&endpoint_b);
	endpoint_a.sock = open_socket(&endpoint_a);
	endpoint_b.sock = open_socket(&endpoint_b);
	/* Start delivering a message once its first kilobyte has arrived */
	if (usrsctp_setsockopt(endpoint_b.sock, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
	    &point, sizeof(point)) < 0) {
		perror("SCTP_PARTIAL_DELIVERY_POINT");
		return (EXIT_FAILURE);
	}
	for (round = 0; round < 10000; round++) {
		if (established(endpoint_a.sock) && established(endpoint_b.sock)) {
			break;
		}
		if (deliver(&endpoint_a) + deliver(&endpoint_b) == 0) {
			usleep(1000);
		}
	}
	if (!established(endpoint_a.sock) || !established(endpoint_b.sock)) {
		fprintf(stderr, "Association not established\n");
		return (EXIT_FAILURE);
	}

	if ((rc = pthread_create(&input, NULL, input_thread, NULL)) != 0 ||
	    (rc = pthread_create(&receive, NULL, receive_thread, NULL)) != 0) {
		fprintf(stderr, "pthread_create: %s\n", strerror(rc));
		exit(EXIT_FAILURE);
	}
	send_messages(unordered);
	pthread_join(receive, NULL);
	atomic_store(&stop, 1);
	pthread_join(input, NULL);
	printf("%u messages received (%s mode)\n", messages, mode_name);

	usrsctp_close(endpoint_a.sock);
	usrsctp_close(endpoint_b.sock);
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
