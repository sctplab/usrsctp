/*-
 * Copyright (c) 2011 Irene Ruengeler
 * Copyright (c) 2011 Michael Tuexen
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __USRSCTP_H__
#define __USRSCTP_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#if !defined(__Userspace_os_Windows)
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if !defined(MSG_NOTIFICATION)
#define MSG_NOTIFICATION 0x2000         /* SCTP notification */
#endif

void
sctp_init(uint16_t);

void
sctp_finish(void);

struct socket *
userspace_socket(int domain,
                 int type,
                 int protocol);

struct socket *
usrsctp_socket(int domain, int type, int protocol,
  int (*receive_cb)(struct socket *sock, struct sctp_queued_to_read* c),
  int (*send_cb)(struct socket *sock, uint32_t sb_free),
  uint32_t sb_threshold);

int
userspace_setsockopt(struct socket *so,
                     int level,
                     int option_name,
                     const void *option_value,
                     socklen_t option_len);

int
userspace_getsockopt(struct socket *so,
                     int level,
                     int option_name,
                     void *option_value,
                     socklen_t option_len);

ssize_t
userspace_sctp_sendmsg(struct socket *so,
                        const void *data,
                        size_t len,
                        struct sockaddr *to,
                        socklen_t tolen,
                        uint32_t ppid,
                        uint32_t flags,
                        uint32_t stream_no,
                        uint32_t timetolive,
                        uint32_t context);

ssize_t
userspace_sctp_sendmbuf(struct socket *so,
                        struct mbuf* mbufdata,
                        size_t len,
                        struct sockaddr *to,
                        socklen_t tolen,
                        uint32_t ppid,
                        uint32_t flags,
                        uint32_t stream_no,
                        uint32_t timetolive,
                        uint32_t context);

ssize_t
userspace_sctp_recvmsg(struct socket *so,
                       void *dbuf,
                       size_t len,
                       struct sockaddr *from,
                       socklen_t * fromlen,
                       struct sctp_sndrcvinfo *sinfo,
                       int *msg_flags);

int
userspace_bind(struct socket *so,
               struct sockaddr *name,
               int namelen);

int
userspace_bindx(struct socket *so,
                struct sockaddr *addrs,
                int addrcnt,
                int flags);

int
userspace_listen(struct socket *so,
                 int backlog);


struct socket *
userspace_accept(struct socket *so,
                 struct sockaddr * aname,
                 socklen_t * anamelen);


int
userspace_connect(struct socket *so,
                  struct sockaddr *name,
                  int namelen);

void
userspace_close(struct socket *so);

int
userspace_finish(void);

int
userspace_shutdown(struct socket *so, int how);

#define SCTP_USERSPACE_SYSCTL_DECL(__field)           \
void userspace_sysctl_set_ ## __field(uint32_t value);\
uint32_t userspace_sysctl_get_ ## __field(void);

SCTP_USERSPACE_SYSCTL_DECL(sctp_sendspace)
SCTP_USERSPACE_SYSCTL_DECL(sctp_recvspace)
SCTP_USERSPACE_SYSCTL_DECL(sctp_auto_asconf)
SCTP_USERSPACE_SYSCTL_DECL(sctp_multiple_asconfs)
SCTP_USERSPACE_SYSCTL_DECL(sctp_ecn_enable)
SCTP_USERSPACE_SYSCTL_DECL(sctp_ecn_nonce)
SCTP_USERSPACE_SYSCTL_DECL(sctp_strict_sacks)
SCTP_USERSPACE_SYSCTL_DECL(sctp_no_csum_on_loopback)
SCTP_USERSPACE_SYSCTL_DECL(sctp_strict_init)
SCTP_USERSPACE_SYSCTL_DECL(sctp_peer_chunk_oh)
SCTP_USERSPACE_SYSCTL_DECL(sctp_max_burst_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_max_chunks_on_queue)
SCTP_USERSPACE_SYSCTL_DECL(sctp_hashtblsize)
SCTP_USERSPACE_SYSCTL_DECL(sctp_pcbtblsize)
SCTP_USERSPACE_SYSCTL_DECL(sctp_min_split_point)
SCTP_USERSPACE_SYSCTL_DECL(sctp_chunkscale)
SCTP_USERSPACE_SYSCTL_DECL(sctp_delayed_sack_time_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_sack_freq_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_system_free_resc_limit)
SCTP_USERSPACE_SYSCTL_DECL(sctp_asoc_free_resc_limit)
SCTP_USERSPACE_SYSCTL_DECL(sctp_heartbeat_interval_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_pmtu_raise_time_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_shutdown_guard_time_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_secret_lifetime_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_rto_max_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_rto_min_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_rto_initial_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_init_rto_max_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_valid_cookie_life_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_init_rtx_max_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_assoc_rtx_max_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_path_rtx_max_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_add_more_threshold)
SCTP_USERSPACE_SYSCTL_DECL(sctp_nr_outgoing_streams_default)
SCTP_USERSPACE_SYSCTL_DECL(sctp_cmt_on_off)
SCTP_USERSPACE_SYSCTL_DECL(sctp_cmt_use_dac)
SCTP_USERSPACE_SYSCTL_DECL(sctp_nr_sack_on_off)
SCTP_USERSPACE_SYSCTL_DECL(sctp_cmt_pf)
SCTP_USERSPACE_SYSCTL_DECL(sctp_use_cwnd_based_maxburst)
SCTP_USERSPACE_SYSCTL_DECL(sctp_early_fr)
SCTP_USERSPACE_SYSCTL_DECL(sctp_early_fr_msec)
SCTP_USERSPACE_SYSCTL_DECL(sctp_asconf_auth_nochk)
SCTP_USERSPACE_SYSCTL_DECL(sctp_auth_disable)
SCTP_USERSPACE_SYSCTL_DECL(sctp_nat_friendly)
SCTP_USERSPACE_SYSCTL_DECL(sctp_L2_abc_variable)
SCTP_USERSPACE_SYSCTL_DECL(sctp_mbuf_threshold_count)
SCTP_USERSPACE_SYSCTL_DECL(sctp_do_drain)
SCTP_USERSPACE_SYSCTL_DECL(sctp_hb_maxburst)
SCTP_USERSPACE_SYSCTL_DECL(sctp_abort_if_one_2_one_hits_limit)
SCTP_USERSPACE_SYSCTL_DECL(sctp_strict_data_order)
SCTP_USERSPACE_SYSCTL_DECL(sctp_min_residual)
SCTP_USERSPACE_SYSCTL_DECL(sctp_max_retran_chunk)
SCTP_USERSPACE_SYSCTL_DECL(sctp_logging_level)
SCTP_USERSPACE_SYSCTL_DECL(sctp_default_cc_module)
SCTP_USERSPACE_SYSCTL_DECL(sctp_default_frag_interleave)
SCTP_USERSPACE_SYSCTL_DECL(sctp_mobility_base)
SCTP_USERSPACE_SYSCTL_DECL(sctp_mobility_fasthandoff)
SCTP_USERSPACE_SYSCTL_DECL(sctp_inits_include_nat_friendly)
SCTP_USERSPACE_SYSCTL_DECL(sctp_udp_tunneling_for_client_enable)
SCTP_USERSPACE_SYSCTL_DECL(sctp_udp_tunneling_port)
SCTP_USERSPACE_SYSCTL_DECL(sctp_enable_sack_immediately)
SCTP_USERSPACE_SYSCTL_DECL(sctp_vtag_time_wait)
#ifdef SCTP_DEBUG
SCTP_USERSPACE_SYSCTL_DECL(sctp_debug_on)
#endif
#ifdef  __cplusplus
}
#endif
#endif
