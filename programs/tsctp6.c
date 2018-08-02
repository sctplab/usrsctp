/*
 * Copyright (C) 2005-2013 Michael Tuexen
 * Copyright (C) 2011-2013 Irene Ruengeler
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

#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <sys/timeb.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#ifdef LINUX
#include <getopt.h>
#endif
#include <usrsctp.h>

/* global for the send callback, but used in kernel version as well */
static unsigned long number_of_messages;
static char *buffer;
static int length;
static union sock_union{
	struct sockaddr sa;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
} remote_addr;
static int unordered;
uint32_t optval = 1;
struct socket *psock = NULL;

static struct timeval start_time;
unsigned int runtime = 0;
static unsigned long messages = 0;
static unsigned long long first_length = 0;
static unsigned long long sum = 0;
static unsigned int use_cb = 0;

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                   \
	do {                                                      \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;    \
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec; \
		if ((vvp)->tv_usec < 0) {                         \
			(vvp)->tv_sec--;                          \
			(vvp)->tv_usec += 1000000;                \
		}                                                 \
	} while (0)
#endif


char Usage[] =
"Usage: tsctp [options] [address]\n"
"Options:\n"
"        -a      set adaptation layer indication\n"
"        -c      use callback API\n"
"        -E      local UDP encapsulation port (default 9899)\n"
"        -f      fragmentation point\n"
"        -l      size of send/receive buffer\n"
"        -L      bind to local address\n"
"        -n      number of messages sent (0 means infinite)/received\n"
"        -D      turns Nagle off\n"
"        -R      socket recv buffer\n"
"        -S      socket send buffer\n"
"        -T      time to send messages\n"
"        -u      use unordered user messages\n"
"        -U      remote UDP encapsulation port\n"
"        -v      verbose\n"
"        -V      very verbose\n"
"        -m      enable path mtu discovery\n"
"        -4      IPv4 only\n"
"        -6      IPv6 only\n"
;

#define DEFAULT_LENGTH             1024
#define DEFAULT_NUMBER_OF_MESSAGES 1024
#define DEFAULT_PORT               5001
#define BUFFERSIZE                 (1<<16)
#define MAX_LOCAL_ADDR             10

static int verbose, very_verbose;
static unsigned int done;

void stop_sender(int sig)
{
	done = 1;
}

#ifdef _WIN32
static void
gettimeofday(struct timeval *tv, void *ignore)
{
	struct timeb tb;

	ftime(&tb);
	tv->tv_sec = (long)tb.time;
 	tv->tv_usec = tb.millitm * 1000;
}
#endif

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
handle_connection(void *arg)
{
	ssize_t n;
	char *buf;
#ifdef _WIN32
	HANDLE tid;
#else
	pthread_t tid;
#endif
	struct socket *conn_sock;
	struct timeval time_start, time_now, time_diff;
	double seconds;
	unsigned long recv_calls = 0;
	unsigned long notifications = 0;
	int flags;
	struct sockaddr addr;
	socklen_t len;
	union sctp_notification *snp;
	struct sctp_paddr_change *spc;
	struct timeval note_time;
	unsigned int infotype;
	struct sctp_recvv_rn rn;
	socklen_t infolen = sizeof(struct sctp_recvv_rn);

	conn_sock = *(struct socket **)arg;
#ifdef _WIN32
	tid = GetCurrentThread();
#else
	tid = pthread_self();
	pthread_detach(tid);
#endif

	buf = malloc(BUFFERSIZE);
	flags = 0;
	len = (socklen_t)0;
	infotype = 0;
	memset(&rn, 0, sizeof(struct sctp_recvv_rn));
	n = usrsctp_recvv(conn_sock, (void*)buf, BUFFERSIZE, (struct sockaddr *) &addr, &len,
	                  (void *)&rn, &infolen, &infotype, &flags);

	gettimeofday(&time_start, NULL);
	while (n > 0) {
		recv_calls++;
		if (flags & MSG_NOTIFICATION) {
			notifications++;
			gettimeofday(&note_time, NULL);
			printf("notification arrived at %f\n", note_time.tv_sec+(double)note_time.tv_usec/1000000.0);
			snp = (union sctp_notification *)buf;
			if (snp->sn_header.sn_type==SCTP_PEER_ADDR_CHANGE)
			{
				spc = &snp->sn_paddr_change;
				printf("SCTP_PEER_ADDR_CHANGE: state=%d, error=%d\n",spc->spc_state, spc->spc_error);
			}
		} else {
			if (very_verbose) {
				printf("Message received\n");
			}
			sum += n;
			if (flags & MSG_EOR) {
				messages++;
				if (first_length == 0)
					first_length = sum;
			}
		}
		flags = 0;
		len = (socklen_t)sizeof(struct sockaddr);
		infolen = sizeof(struct sctp_recvv_rn);
		infotype = 0;
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));
		n = usrsctp_recvv(conn_sock, (void *) buf, BUFFERSIZE, (struct sockaddr *) &addr, &len, (void *)&rn,
		                  &infolen, &infotype, &flags);
	}
	if (n < 0)
		perror("usrsctp_recvv");
	gettimeofday(&time_now, NULL);
	timersub(&time_now, &time_start, &time_diff);
	seconds = time_diff.tv_sec + (double)time_diff.tv_usec/1000000.0;
	printf("%llu, %lu, %lu, %lu, %llu, %f, %f\n",
	        first_length, messages, recv_calls, notifications, sum, seconds, (double)first_length * (double)messages / seconds);
	fflush(stdout);
	usrsctp_close(conn_sock);
	free(buf);
#ifdef _WIN32
	return 0;
#else
	return (NULL);
#endif
}

static int
send_cb(struct socket *sock, uint32_t sb_free) {
	struct sctp_sndinfo sndinfo;

	if ((messages == 0) & verbose) {
		printf("Start sending ");
		if (number_of_messages > 0) {
			printf("%ld messages ", (long)number_of_messages);
		}
		if (runtime > 0) {
			printf("for %u seconds ...", runtime);
		}
		printf("\n");
		fflush(stdout);
	}

	sndinfo.snd_sid = 0;
	sndinfo.snd_flags = 0;
	if (unordered != 0) {
		sndinfo.snd_flags |= SCTP_UNORDERED;
	}
	sndinfo.snd_ppid = 0;
	sndinfo.snd_context = 0;
	sndinfo.snd_assoc_id = 0;

	while (!done && ((number_of_messages == 0) || (messages < (number_of_messages - 1)))) {
		char temp[INET6_ADDRSTRLEN];
		if (very_verbose) {
			printf("Sending message number %lu.\n", messages + 1);
			if (remote_addr.sa.sa_family == AF_INET) {
				fprintf(stdout,"Send message to %s:%d\n", inet_ntop(AF_INET, &remote_addr.s4.sin_addr, temp, INET_ADDRSTRLEN), ntohs(remote_addr.s4.sin_port));
			} else {
				fprintf(stdout,"Send message to %s:%d\n", inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, temp, INET6_ADDRSTRLEN), ntohs(remote_addr.s6.sin6_port));
			}
		}

		if (usrsctp_sendv(psock, buffer, length,
		                  (struct sockaddr *) &remote_addr, 1,
		                  (void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
		                  0) < 0) {
			if (errno != EWOULDBLOCK && errno != EAGAIN) {
				perror("usrsctp_sendv (cb)");
				exit(1);
			} else {
				if (very_verbose){
					printf("EWOULDBLOCK or EAGAIN for message number %lu - will retry\n", messages + 1);
				}
				/* send until EWOULDBLOCK then exit callback. */
				return (1);
			}
		}
		messages++;
	}
	if ((done == 1) || (messages == (number_of_messages - 1))) {
		if (very_verbose)
			printf("Sending final message number %lu.\n", messages + 1);

		sndinfo.snd_flags |= SCTP_EOF;
		if (usrsctp_sendv(psock, buffer, length, (struct sockaddr *) &remote_addr, 1,
		                  (void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
		                  0) < 0) {
			if (errno != EWOULDBLOCK && errno != EAGAIN) {
				perror("usrsctp_sendv (cb)");
				exit(1);
			} else {
				if (very_verbose){
					printf("EWOULDBLOCK or EAGAIN for final message number %lu - will retry\n", messages + 1);
				}
				/* send until EWOULDBLOCK then exit callback. */
				return (1);
			}
		}
		messages++;
		done = 2;
	}

	return (1);
}

static int
server_receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	struct timeval now, diff_time;
	double seconds;

	if (data == NULL) {
		gettimeofday(&now, NULL);
		timersub(&now, &start_time, &diff_time);
		seconds = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;
		printf("%llu, %lu, %llu, %f, %f\n",
			first_length, messages, sum, seconds, (double)first_length * (double)messages / seconds);
		usrsctp_close(sock);
		first_length = 0;
		sum = 0;
		messages = 0;
		return (1);
	}
	if (first_length == 0) {
		first_length = (unsigned int)datalen;
		gettimeofday(&start_time, NULL);
	}
	sum += datalen;
	messages++;

	free(data);
	return (1);
}

static int
client_receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	free(data);
	return (1);
}

void
debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

int main(int argc, char **argv)
{
#ifndef _WIN32
	int c;
#endif
	socklen_t addr_len;
	unsigned int nr_local_addr = 0;
	struct sockaddr_storage local_addr[MAX_LOCAL_ADDR];
	char *local_addr_ptr = (char*) local_addr;
	struct timeval time_start, time_now, time_diff;
	int client;
	uint16_t local_port, remote_port, port, local_udp_port, remote_udp_port, i;
	int rcvbufsize=0, sndbufsize=0, myrcvbufsize, mysndbufsize;
	socklen_t intlen;
	double seconds;
	double throughput;
	int nodelay = 0, enable_pmtu = 0;;
	struct sctp_assoc_value av;
	struct sctp_udpencaps encaps;
	struct sctp_sndinfo sndinfo;
#ifdef _WIN32
	HANDLE tid;
#else
	pthread_t tid;
#endif
	int fragpoint = 0;
	struct sctp_setadaptation ind = {0};
#ifdef _WIN32
	char *opt;
	int optind;
#endif
	int ipv4only = 0;
	int ipv6only = 0;

	unordered = 0;
	length = DEFAULT_LENGTH;
	number_of_messages = DEFAULT_NUMBER_OF_MESSAGES;
	port = DEFAULT_PORT;
	remote_udp_port = 0;
	local_udp_port = 9899;
	verbose = 0;
	very_verbose = 0;

	memset((void *) &remote_addr, 0, sizeof(remote_addr));

#ifndef _WIN32
	while ((c = getopt(argc, argv, "a:cp:l:E:f:L:n:R:S:T:uU:vVDm46")) != -1)
		switch(c) {
			case 'a':
				ind.ssb_adaptation_ind = atoi(optarg);
				break;
			case 'c':
				use_cb = 1;
				break;
			case 'l':
				length = atoi(optarg);
				break;
			case 'm':
				enable_pmtu = 1;
				break;
			case 'n':
				number_of_messages = atoi(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'E':
				local_udp_port = atoi(optarg);
				break;
			case 'f':
				fragpoint = atoi(optarg);
				break;
			case 'L':
				if (nr_local_addr < MAX_LOCAL_ADDR) {
					struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr_ptr;
					struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr_ptr;

					if (inet_pton(AF_INET6, optarg, &s6->sin6_addr)) {
						s6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
						s6->sin6_len = sizeof(struct sockaddr_in6);
#endif
						local_addr_ptr += sizeof(struct sockaddr_in6);
						nr_local_addr++;
					} else {
						if (inet_pton(AF_INET, optarg, &s4->sin_addr)) {
							s4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
							s4->sin_len = sizeof(struct sockaddr_in);
#endif
							local_addr_ptr += sizeof(struct sockaddr_in);
							nr_local_addr++;
						} else {
							printf("Invalid address\n");
							fprintf(stderr, "%s", Usage);
							exit(1);
						}
					}
				}
				break;
			case 'R':
				rcvbufsize = atoi(optarg);
				break;
			case 'S':
				sndbufsize = atoi(optarg);
				break;
			case 'T':
				runtime = atoi(optarg);
				number_of_messages = 0;
				break;
			case 'u':
				unordered = 1;
				break;
			case 'U':
				remote_udp_port = atoi(optarg);
				break;
			case 'v':
				verbose = 1;
				break;
			case 'V':
				verbose = 1;
				very_verbose = 1;
				break;
			case 'D':
				nodelay = 1;
				break;
			case '4':
				ipv4only = 1;
				if (ipv6only) {
					printf("IPv6 only already\n");
					exit(1);
				}
				break;
			case '6':
				ipv6only = 1;
				if (ipv4only) {
					printf("IPv4 only already\n");
					exit(1);
				}
				break;
			default:
				fprintf(stderr, "%s", Usage);
				exit(1);
		}
#else
	for (optind = 1; optind < argc; optind++) {
		if (argv[optind][0] == '-') {
			switch (argv[optind][1]) {
				case 'a':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					ind.ssb_adaptation_ind = atoi(opt);
					break;
				case 'c':
					use_cb = 1;
					break;
				case 'l':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					length = atoi(opt);
					break;
				case 'p':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					port = atoi(opt);
					break;
				case 'n':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					number_of_messages = atoi(opt);
					break;
				case 'f':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					fragpoint = atoi(opt);
					break;
				case 'L':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					if (nr_local_addr < MAX_LOCAL_ADDR) {
						struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr_ptr;
						struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr_ptr;

						if (inet_pton(AF_INET6, opt, &s6->sin6_addr)) {
							s6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
							s6->sin6_len = sizeof(struct sockaddr_in6);
#endif
							local_addr_ptr += sizeof(struct sockaddr_in6);
							nr_local_addr++;
						} else {
							if (inet_pton(AF_INET, opt, &s4->sin_addr)) {
								s4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
								s4->sin_len = sizeof(struct sockaddr_in);
#endif
								local_addr_ptr += sizeof(struct sockaddr_in);
								nr_local_addr++;
							} else {
								printf("Invalid address\n");
								fprintf(stderr, "%s", Usage);
								exit(1);
							}
						}
					}
					break;
				case 'U':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					remote_udp_port = atoi(opt);
					break;
				case 'E':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					local_udp_port = atoi(opt);
					break;
				case 'R':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					rcvbufsize = atoi(opt);
					break;
				case 'S':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					sndbufsize = atoi(opt);
					break;
				case 'T':
					if (++optind >= argc) {
						printf("%s", Usage);
						exit(1);
					}
					opt = argv[optind];
					runtime = atoi(opt);
					number_of_messages = 0;
					break;
				case 'u':
					unordered = 1;
					break;
				case 'v':
					verbose = 1;
					break;
				case 'V':
					verbose = 1;
					very_verbose = 1;
					break;
				case 'D':
					nodelay = 1;
					break;
				case 'm':
					enable_pmtu = 1;
					break;
				case '4':
					ipv4only = 1;
					if (ipv6only) {
						printf("IPv6 only already\n");
						exit(1);
					}
					break;
				case '6':
					ipv6only = 1;
					if (ipv4only) {
						printf("IPv4 only already\n");
						exit(1);
					}
					break;
				default:
					printf("%s", Usage);
					exit(1);
			}
		} else {
			break;
		}
	}
#endif
	if (optind == argc) {
		client      = 0;
		local_port  = port;
		remote_port = 0;
	} else {
		client      = 1;
		local_port  = 0;
		remote_port = port;
	}

	if (nr_local_addr == 0) {
		memset((void *) local_addr, 0, sizeof(local_addr));
		if (ipv4only) {
			struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr;
			s4->sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
			s4->sin_len         = sizeof(struct sockaddr_in);
#endif
			s4->sin_addr.s_addr = htonl(INADDR_ANY);
		} else {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr;
			s6->sin6_family      = AF_INET6;
#ifdef HAVE_SIN6_LEN
			s6->sin6_len         = sizeof(struct sockaddr_in6);
#endif
			s6->sin6_addr = in6addr_any;
		}
		nr_local_addr = 1;
	}
	local_addr_ptr = (char*) local_addr;
	for (i = 0; i < nr_local_addr; i++) {
		struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr_ptr;
		struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr_ptr;

		if (s4->sin_family == AF_INET) {
			s4->sin_port = htons(local_port);
			local_addr_ptr += sizeof(struct sockaddr_in);
			if (ipv6only) {
				printf("Can't use IPv4 address when IPv6 only\n");
				exit(1);
			}
		} else if (s6->sin6_family == AF_INET6) {
			s6->sin6_port = htons(local_port);
			local_addr_ptr += sizeof(struct sockaddr_in6);
			if (ipv4only) {
				printf("Can't use IPv6 address when IPv4 only\n");
				exit(1);
			}
		}
	}

	usrsctp_init(local_udp_port, NULL, debug_printf);
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	usrsctp_sysctl_set_sctp_blackhole(2);
	usrsctp_sysctl_set_sctp_enable_sack_immediately(1);
	if (enable_pmtu == 1) {
		usrsctp_sysctl_set_sctp_plpmtud_enable(1);
	}

	if (client) {
		if (use_cb) {
			if (!(psock = usrsctp_socket((ipv4only ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_SCTP, client_receive_cb, send_cb, length, NULL))) {
				perror("usersctp_socket");
				exit(1);
			}
		} else {
			if (!(psock = usrsctp_socket((ipv4only ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL))) {
				perror("usersctp_socket");
				exit(1);
			}
		}
	} else {
		if (use_cb) {
			if (!(psock = usrsctp_socket((ipv4only ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_SCTP, server_receive_cb, NULL, 0, NULL))) {
				perror("usersctp_socket");
				exit(1);
			}
		} else {
			if (!(psock = usrsctp_socket((ipv4only ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL))) {
				perror("usersctp_socket");
				exit(1);
			}
		}
	}



	if (nr_local_addr > 0) {
		if (usrsctp_bindx(psock, (struct sockaddr *)local_addr, nr_local_addr, SCTP_BINDX_ADD_ADDR) != 0) {
			perror("usrsctp_bindx");
			exit(1);
		}
	}

	if (ind.ssb_adaptation_ind > 0) {
		if (usrsctp_setsockopt(psock, IPPROTO_SCTP, SCTP_ADAPTATION_LAYER, (const void*)&ind, (socklen_t)sizeof(struct sctp_setadaptation)) < 0) {
			perror("usrsctp_setsockopt");
		}
	}

	if (!client) {
		if (rcvbufsize) {
			if (usrsctp_setsockopt(psock, SOL_SOCKET, SO_RCVBUF, &rcvbufsize, sizeof(int)) < 0) {
				perror("usrsctp_setsockopt: rcvbuf");
			}
		}
		if (verbose) {
			intlen = sizeof(int);
			if (usrsctp_getsockopt(psock, SOL_SOCKET, SO_RCVBUF, &myrcvbufsize, (socklen_t *)&intlen) < 0) {
				perror("usrsctp_getsockopt: rcvbuf");
			} else {
				fprintf(stdout,"Receive buffer size: %d.\n", myrcvbufsize);
			}
		}

		if (usrsctp_listen(psock, 1) < 0) {
			perror("usrsctp_listen");
			exit(1);
		}

		while (1) {
			memset(&remote_addr, 0, sizeof(remote_addr));
			if (ipv4only) {
				addr_len = sizeof(struct sockaddr_in);
			} else {
				addr_len = sizeof(struct sockaddr_in6);
			}

			if (use_cb) {
				struct socket *conn_sock;

				if ((conn_sock = usrsctp_accept(psock, (struct sockaddr *) &remote_addr, &addr_len))== NULL) {
					perror("usrsctp_accept");
					continue;
				}
			} else {
				struct socket **conn_sock;

				conn_sock = (struct socket **)malloc(sizeof(struct socket *));
				if ((*conn_sock = usrsctp_accept(psock, (struct sockaddr *)&remote_addr, &addr_len)) == NULL) {
					perror("usrsctp_accept");
					continue;
				}
#ifdef _WIN32
				tid = CreateThread(NULL, 0, &handle_connection, (void *)conn_sock, 0, NULL);
#else
				pthread_create(&tid, NULL, &handle_connection, (void *)conn_sock);
#endif
			}
			if (verbose) {
				char temp[INET6_ADDRSTRLEN];

				if (remote_addr.sa.sa_family == AF_INET) {
					fprintf(stdout,"Connection accepted from %s:%d\n", inet_ntop(AF_INET, &remote_addr.s4.sin_addr, temp, INET_ADDRSTRLEN), ntohs(remote_addr.s4.sin_port));
				} else {
					fprintf(stdout,"Connection accepted from %s:%d\n", inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, temp, INET6_ADDRSTRLEN), ntohs(remote_addr.s6.sin6_port));
				}
			}
		}
	} else {
		if (inet_pton(AF_INET6, argv[optind], &remote_addr.s6.sin6_addr)) {
			remote_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			remote_addr.s6.sin6_port = htons(remote_port);
			addr_len = sizeof(struct sockaddr_in6);

			if (ipv4only) {
				printf("Can't use IPv6 address when IPv4 only\n");
				exit(1);
			}
		} else {
			if (inet_pton(AF_INET, argv[optind], &remote_addr.s4.sin_addr))
			{
				remote_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
				remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
				remote_addr.s4.sin_port = htons(remote_port);
				addr_len = sizeof(struct sockaddr_in);

				if (ipv6only) {
					printf("Can't use IPv4 address when IPv6 only\n");
					exit(1);
				}
			} else {
				printf("Invalid address\n");
				fprintf(stderr, "%s", Usage);
				exit(1);
			}
		}

		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = remote_addr.sa.sa_family;
		encaps.sue_port = htons(remote_udp_port);
		if (usrsctp_setsockopt(psock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
			perror("usrsctp_setsockopt");
		}

		if (nodelay == 1) {
			optval = 1;
		} else {
			optval = 0;
		}
		if (usrsctp_setsockopt(psock, IPPROTO_SCTP, SCTP_NODELAY, &optval, sizeof(int)) < 0) {
			perror("usrsctp_setsockopt: nodelay");
		}

		if (fragpoint) {
			av.assoc_id = 0;
			av.assoc_value = fragpoint;
			if (usrsctp_setsockopt(psock, IPPROTO_SCTP, SCTP_MAXSEG, &av, sizeof(av)) < 0) {
				perror("setsockopt: SCTP_MAXSEG");
			}
		}

		if (sndbufsize)
			if (usrsctp_setsockopt(psock, SOL_SOCKET, SO_SNDBUF, &sndbufsize, sizeof(int)) < 0) {
				perror("usrsctp_setsockopt: sndbuf");
			}

		if (verbose) {
			intlen = sizeof(int);
			if (usrsctp_getsockopt(psock, SOL_SOCKET, SO_SNDBUF, &mysndbufsize, (socklen_t *)&intlen) < 0) {
				perror("usrsctp_getsockopt: sndbuf");
			} else {
				fprintf(stdout,"Send buffer size: %d.\n", mysndbufsize);
			}
		}

		buffer = malloc(length);
		memset(buffer, 'A', length);

		if (usrsctp_connect(psock, (struct sockaddr *) &remote_addr, addr_len) == -1 ) {
			perror("usrsctp_connect");
			exit(1);
		}

		gettimeofday(&time_start, NULL);
		if (verbose && !very_verbose) {
			printf("Start sending %ld messages...", (long)number_of_messages);
			fflush(stdout);
		}

		done = 0;

		if (runtime > 0) {
#ifndef _WIN32
			signal(SIGALRM, stop_sender);
			alarm(runtime);
#else
			printf("You cannot set the runtime in Windows yet\n");
			exit(-1);
#endif
		}

		if (use_cb) {
			while (done < 2 && (messages < (number_of_messages - 1))) {
#ifdef _WIN32
				Sleep(1000);
#else
				sleep(1);
#endif
			}
		} else {
			sndinfo.snd_sid = 0;
			sndinfo.snd_flags = 0;
			if (unordered != 0) {
				sndinfo.snd_flags |= SCTP_UNORDERED;
			}
			sndinfo.snd_ppid = 0;
			sndinfo.snd_context = 0;
			sndinfo.snd_assoc_id = 0;
			if (verbose) {
				printf("Start sending ");
				if (number_of_messages > 0) {
					printf("%ld messages ", (long)number_of_messages);
				}
				if (runtime > 0) {
					printf("for %u seconds ...", runtime);
				}
				printf("\n");
				fflush(stdout);
			}
			while (!done && ((number_of_messages == 0) || (messages < (number_of_messages - 1)))) {
				char temp[INET6_ADDRSTRLEN];
				if (very_verbose) {
					printf("Sending message number %lu.\n", messages + 1);
				}

				if (remote_addr.sa.sa_family == AF_INET) {
					fprintf(stdout,"Send message to %s:%d\n", inet_ntop(AF_INET, &remote_addr.s4.sin_addr, temp, INET_ADDRSTRLEN), ntohs(remote_addr.s4.sin_port));
				} else {
					fprintf(stdout,"Send message to %s:%d\n", inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, temp, INET6_ADDRSTRLEN), ntohs(remote_addr.s6.sin6_port));
				}

				if (usrsctp_sendv(psock, buffer, length, (struct sockaddr *) &remote_addr, 1,
				                  (void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
				                  0) < 0) {
					perror("usrsctp_sendv");
					exit(1);
				}
				messages++;
			}
			if (very_verbose) {
				printf("Sending message number %lu.\n", messages + 1);
			}

			sndinfo.snd_flags |= SCTP_EOF;
			if (usrsctp_sendv(psock, buffer, length, (struct sockaddr *) &remote_addr, 1,
			                  (void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
			                  0) < 0) {
				perror("usrsctp_sendv");
				exit(1);
			}
			messages++;
		}
		free (buffer);

		if (verbose) {
			printf("Closing socket.\n");
		}

		usrsctp_close(psock);
		gettimeofday(&time_now, NULL);
		timersub(&time_now, &time_start, &time_diff);
		seconds = time_diff.tv_sec + (double)time_diff.tv_usec/1000000;
		printf("%s of %ld messages of length %u took %f seconds.\n",
		       "Sending", messages, length, seconds);
		throughput = (double)messages * (double)length / seconds;
		printf("Throughput was %f Byte/sec.\n", throughput);
	}

	while (usrsctp_finish() != 0) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return 0;
}
