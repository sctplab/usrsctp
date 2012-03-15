/*-
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2011, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2011, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*	$KAME: sctp6_usrreq.c,v 1.38 2005/08/24 08:08:56 suz Exp $	*/

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/netinet6/sctp6_usrreq.c 233005 2012-03-15 14:22:05Z tuexen $");
#endif

#include <netinet/sctp_os.h>
#ifdef __FreeBSD__
#include <sys/proc.h>
#endif
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#if defined(INET6)
#include <netinet6/sctp6_var.h>
#endif
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_auth.h>
#include <netinet/sctp_input.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_bsd_addr.h>
#include <netinet/sctp_crc32.h>
#if !defined(__Userspace_os_Windows)
#include <netinet/udp.h>
#endif

#if defined(__APPLE__)
#define APPLE_FILE_NO 9
#endif
#ifdef IPSEC
#include <netipsec/ipsec.h>
#if defined(INET6)
#include <netipsec/ipsec6.h>
#endif /* INET6 */
#endif /* IPSEC */

#if !defined (__Userspace__)
extern struct protosw inetsw[];
#endif
#if defined (__Panda__) || defined (__Userspace__)
int ip6_v6only=0;
#endif
#if defined(__Userspace__)
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
#if defined(__Userspace_os_Windows)
	uint32_t temp;
#endif
	bzero(sin, sizeof(*sin));
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
	sin->sin_len = sizeof(struct sockaddr_in);
#endif
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
#if defined(__Userspace_os_Windows)
	temp = sin6->sin6_addr.s6_addr16[7];
	temp = temp << 16;
	temp = temp | sin6->sin6_addr.s6_addr16[6];
	sin->sin_addr.s_addr = temp;
	sctp_print_address((struct sockaddr*)sin); 
#else
	sin->sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];
#endif
}

void
in6_sin6_2_sin_in_sock(struct sockaddr *nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 sin6;

	/* save original sockaddr_in6 addr and convert it to sockaddr_in  */
	sin6 = *(struct sockaddr_in6 *)nam;
	sin_p = (struct sockaddr_in *)nam;
	in6_sin6_2_sin(sin_p, &sin6);
}
#endif

int
#if defined(__APPLE__) || defined (__Userspace__)
sctp6_input_with_port(struct mbuf **i_pak, int *offp, uint16_t port)
#elif defined( __Panda__)
sctp6_input(pakhandle_type *i_pak)
#else
sctp6_input(struct mbuf **i_pak, int *offp, int proto)
#endif
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct sctphdr *sh;
	struct sctp_inpcb *in6p = NULL;
	struct sctp_nets *net;
	int refcount_up = 0;
	uint32_t vrf_id = 0;
#ifdef IPSEC
	struct inpcb *in6p_ip;
#endif
	struct sctp_chunkhdr *ch;
	int length, offset, iphlen;
	uint8_t ecn_bits;
	struct sctp_tcb *stcb = NULL;
	int pkt_len = 0;
#if !defined(SCTP_WITH_NO_CSUM)
	uint32_t check, calc_check;
#endif
#ifndef __Panda__
	int off = *offp;
#else
	int off;
#endif
#if !defined(__APPLE__) && !defined (__Userspace__)
	uint16_t port = 0;
#endif
#ifdef __Panda__
	/*-
	 * This is Evil, but its the only way to make
	 * panda work right
	 */
	off = sizeof(struct ip6_hdr);
#endif
	/* get the VRF and table id's */
 	if (SCTP_GET_PKT_VRFID(*i_pak, vrf_id)) {
		SCTP_RELEASE_PKT(*i_pak);
		return (-1);
	}

	m = SCTP_HEADER_TO_CHAIN(*i_pak);
	pkt_len = SCTP_HEADER_LEN((*i_pak));
#ifdef __Panda__
	/* We dont need the pak hdr, free it */
	/* For BSD/MAC this does nothing */
	SCTP_DETACH_HEADER_FROM_CHAIN(*i_pak);
	(void)SCTP_RELEASE_HEADER(*i_pak);
#endif

#ifdef  SCTP_PACKET_LOGGING
	sctp_packet_log(m, pkt_len);
#endif
	ip6 = mtod(m, struct ip6_hdr *);
	/* Ensure that (sctphdr + sctp_chunkhdr) in a row. */
	IP6_EXTHDR_GET(sh, struct sctphdr *, m, off,
		       (int)(sizeof(*sh) + sizeof(*ch)));
	if (sh == NULL) {
		SCTP_STAT_INCR(sctps_hdrops);
		return (IPPROTO_DONE);
	}
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));
	iphlen = off;
	offset = iphlen + sizeof(*sh) + sizeof(*ch);
	SCTPDBG(SCTP_DEBUG_INPUT1,
		"sctp6_input() length:%d iphlen:%d\n", pkt_len, iphlen);


#if defined(NFAITH) && NFAITH > 0
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version <= 430000
#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6h->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		goto bad;
	}
#endif
#else

#ifdef __FreeBSD__
	if (faithprefix_p != NULL && (*faithprefix_p) (&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		goto bad;
	}
#else
	if (faithprefix(&ip6->ip6_dst))
		goto bad;
#endif
#endif				/* __FreeBSD_cc_version */

#endif				/* NFAITH defined and > 0 */
	SCTP_STAT_INCR(sctps_recvpackets);
	SCTP_STAT_INCR_COUNTER64(sctps_inpackets);
	SCTPDBG(SCTP_DEBUG_INPUT1, "V6 input gets a packet iphlen:%d pktlen:%d\n",
		iphlen, pkt_len);
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		/* No multi-cast support in SCTP */
		goto bad;
	}
	/* destination port of 0 is illegal, based on RFC2960. */
	if (sh->dest_port == 0)
		goto bad;

#if defined(__FreeBSD__)
#if __FreeBSD_version >= 800000
	SCTPDBG(SCTP_DEBUG_CRCOFFLOAD,
		"sctp_input(): Packet of length %d received on %s with csum_flags 0x%x.\n",
		m->m_pkthdr.len,
		if_name(m->m_pkthdr.rcvif),
		m->m_pkthdr.csum_flags);
#else
	SCTPDBG(SCTP_DEBUG_CRCOFFLOAD,
		"sctp_input(): Packet of length %d received on %s with csum_flags 0x%x.\n",
		m->m_pkthdr.len,
		m->m_pkthdr.rcvif->if_xname,
		m->m_pkthdr.csum_flags);
#endif
#endif
#if defined(__APPLE__)
	SCTPDBG(SCTP_DEBUG_CRCOFFLOAD,
		"sctp_input(): Packet of length %d received on %s%d with csum_flags 0x%x.\n",
		m->m_pkthdr.len,
		m->m_pkthdr.rcvif->if_name,
		m->m_pkthdr.rcvif->if_unit,
		m->m_pkthdr.csum_flags);
#endif
#if defined(__Windows__)
	SCTPDBG(SCTP_DEBUG_CRCOFFLOAD,
		"sctp_input(): Packet of length %d received on %s with csum_flags 0x%x.\n",
		m->m_pkthdr.len,
		m->m_pkthdr.rcvif->if_xname,
		m->m_pkthdr.csum_flags);
#endif
#if defined(SCTP_WITH_NO_CSUM)
	SCTP_STAT_INCR(sctps_recvnocrc);
#else
#if defined(__FreeBSD__) && __FreeBSD_version >= 800000
	if (m->m_pkthdr.csum_flags & CSUM_SCTP_VALID) {
		SCTP_STAT_INCR(sctps_recvhwcrc);
		goto sctp_skip_csum;
	}
#endif
	check = sh->checksum;	/* save incoming checksum */
	if ((check == 0) && (SCTP_BASE_SYSCTL(sctp_no_csum_on_loopback)) &&
	    (IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &ip6->ip6_dst))) {
		SCTP_STAT_INCR(sctps_recvnocrc);
		goto sctp_skip_csum;
	}
	sh->checksum = 0;	/* prepare for calc */
	calc_check = sctp_calculate_cksum(m, iphlen);
	SCTP_STAT_INCR(sctps_recvswcrc);
	if (calc_check != check) {
		SCTPDBG(SCTP_DEBUG_INPUT1, "Bad CSUM on SCTP packet calc_check:%x check:%x  m:%p phlen:%d\n",
			calc_check, check, m, iphlen);
		stcb = sctp_findassociation_addr(m, offset - sizeof(*ch),
						 sh, ch, &in6p, &net, vrf_id);
		if ((net) && (port)) {
			if (net->port == 0) {
				sctp_pathmtu_adjustment(stcb, net->mtu - sizeof(struct udphdr));
			}
			net->port = port;
		}
#if defined(__FreeBSD__)
		if ((net != NULL) && (m->m_flags & M_FLOWID)) {
			net->flowid = m->m_pkthdr.flowid;
#ifdef INVARIANTS
			net->flowidset = 1;
#endif
		}
#endif
		/* in6p's ref-count increased && stcb locked */
		if ((in6p) && (stcb)) {
			sctp_send_packet_dropped(stcb, net, m, iphlen, 1);
			sctp_chunk_output((struct sctp_inpcb *)in6p, stcb, SCTP_OUTPUT_FROM_INPUT_ERROR, SCTP_SO_NOT_LOCKED);
		} else if ((in6p != NULL) && (stcb == NULL)) {
			refcount_up = 1;
		}
		SCTP_STAT_INCR(sctps_badsum);
		SCTP_STAT_INCR_COUNTER32(sctps_checksumerrors);
		goto bad;
	}
	sh->checksum = calc_check;

 sctp_skip_csum:
#endif
	net = NULL;
	/*
	 * Locate pcb and tcb for datagram sctp_findassociation_addr() wants
	 * IP/SCTP/first chunk header...
	 */
	stcb = sctp_findassociation_addr(m, offset - sizeof(*ch),
					 sh, ch, &in6p, &net, vrf_id);
	if ((net) && (port)) {
		if (net->port == 0) {
			sctp_pathmtu_adjustment(stcb, net->mtu - sizeof(struct udphdr));
		}
		net->port = port;
	}
#if defined(__FreeBSD__)
	if ((net != NULL) && (m->m_flags & M_FLOWID)) {
		net->flowid = m->m_pkthdr.flowid;
#ifdef INVARIANTS
		net->flowidset = 1;
#endif
	}
#endif
	/* in6p's ref-count increased */
	if (in6p == NULL) {
		struct sctp_init_chunk *init_chk, chunk_buf;

		SCTP_STAT_INCR(sctps_noport);
		if (ch->chunk_type == SCTP_INITIATION) {
			/*
			 * we do a trick here to get the INIT tag, dig in
			 * and get the tag from the INIT and put it in the
			 * common header.
			 */
			init_chk = (struct sctp_init_chunk *)sctp_m_getptr(m,
									   iphlen + sizeof(*sh), sizeof(*init_chk),
									   (uint8_t *) & chunk_buf);
			if (init_chk)
				sh->v_tag = init_chk->init.initiate_tag;
			else
				sh->v_tag = 0;
		}
		if (ch->chunk_type == SCTP_SHUTDOWN_ACK) {
			sctp_send_shutdown_complete2(m, sh, vrf_id, port);
			goto bad;
		}
		if (ch->chunk_type == SCTP_SHUTDOWN_COMPLETE) {
			goto bad;
		}
		if (ch->chunk_type != SCTP_ABORT_ASSOCIATION) {
			if ((SCTP_BASE_SYSCTL(sctp_blackhole) == 0) ||
			    ((SCTP_BASE_SYSCTL(sctp_blackhole) == 1) &&
			     (ch->chunk_type != SCTP_INIT))) {
				sctp_send_abort(m, iphlen, sh, 0, NULL, vrf_id, port);
			}
		}
		goto bad;
	} else if (stcb == NULL) {
		refcount_up = 1;
	}
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	in6p_ip = (struct inpcb *)in6p;
	if (in6p_ip && (ipsec6_in_reject(m, in6p_ip))) {
/* XXX */
#ifdef __APPLE__
		/* FIX ME: need to find right stat for __APPLE__ */
#endif
#ifndef __APPLE__
		MODULE_GLOBAL(ipsec6stat).in_polvio++;
#endif
		goto bad;
	}
#endif /* IPSEC */

	/*
	 * CONTROL chunk processing
	 */
	offset -= sizeof(*ch);
	ecn_bits = ((ntohl(ip6->ip6_flow) >> 20) & 0x000000ff);

	/* Length now holds the total packet length payload + iphlen */
	length = ntohs(ip6->ip6_plen) + iphlen;

	/*sa_ignore NO_NULL_CHK*/
	sctp_common_input_processing(&m, iphlen, offset, length, sh, ch,
				     in6p, stcb, net, ecn_bits, vrf_id, port);
	/* inp's ref-count reduced && stcb unlocked */
	/* XXX this stuff below gets moved to appropriate parts later... */
	if (m)
		sctp_m_freem(m);
	if ((in6p) && refcount_up) {
		/* reduce ref-count */
		SCTP_INP_WLOCK(in6p);
		SCTP_INP_DECR_REF(in6p);
		SCTP_INP_WUNLOCK(in6p);
	}
	return (IPPROTO_DONE);

 bad:
	if (stcb) {
		SCTP_TCB_UNLOCK(stcb);
	}

	if ((in6p) && refcount_up) {
		/* reduce ref-count */
		SCTP_INP_WLOCK(in6p);
		SCTP_INP_DECR_REF(in6p);
		SCTP_INP_WUNLOCK(in6p);
	}
	if (m)
		sctp_m_freem(m);
	return (IPPROTO_DONE);
}

#if defined(__APPLE__)
int
sctp6_input(struct mbuf **i_pak, int *offp)
{
	return (sctp6_input_with_port(i_pak, offp, 0));
}
#endif

#if !defined(__Userspace__)
#if defined(__Panda__)
void
#else
static void
#endif
sctp6_notify_mbuf(struct sctp_inpcb *inp, struct icmp6_hdr *icmp6,
		  struct sctphdr *sh, struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t nxtsz;

	if ((inp == NULL) || (stcb == NULL) || (net == NULL) ||
	    (icmp6 == NULL) || (sh == NULL)) {
		goto out;
	}
	/* First do we even look at it? */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag))
		goto out;

	if (icmp6->icmp6_type != ICMP6_PACKET_TOO_BIG) {
		/* not PACKET TO BIG */
		goto out;
	}
	/*
	 * ok we need to look closely. We could even get smarter and look at
	 * anyone that we sent to in case we get a different ICMP that tells
	 * us there is no way to reach a host, but for this impl, all we
	 * care about is MTU discovery.
	 */
	nxtsz = ntohl(icmp6->icmp6_mtu);
	/* Stop any PMTU timer */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL, SCTP_FROM_SCTP6_USRREQ+SCTP_LOC_1);

	/* Adjust destination size limit */
	if (net->mtu > nxtsz) {
		net->mtu = nxtsz;
		if (net->port) {
			net->mtu -= sizeof(struct udphdr);
		}
	}
	/* now what about the ep? */
	if (stcb->asoc.smallest_mtu > nxtsz) {
		struct sctp_tmit_chunk *chk;

		/* Adjust that too */
		stcb->asoc.smallest_mtu = nxtsz;
		/* now off to subtract IP_DF flag if needed */

		TAILQ_FOREACH(chk, &stcb->asoc.send_queue, sctp_next) {
			if ((uint32_t) (chk->send_size + IP_HDR_SIZE) > nxtsz) {
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
			}
		}
		TAILQ_FOREACH(chk, &stcb->asoc.sent_queue, sctp_next) {
			if ((uint32_t) (chk->send_size + IP_HDR_SIZE) > nxtsz) {
				/*
				 * For this guy we also mark for immediate
				 * resend since we sent to big of chunk
				 */
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
				if (chk->sent != SCTP_DATAGRAM_RESEND)
					stcb->asoc.sent_queue_retran_cnt++;
				chk->sent = SCTP_DATAGRAM_RESEND;
				chk->rec.data.doing_fast_retransmit = 0;

				chk->sent = SCTP_DATAGRAM_RESEND;
				/* Clear any time so NO RTT is being done */
				chk->sent_rcv_time.tv_sec = 0;
				chk->sent_rcv_time.tv_usec = 0;
				stcb->asoc.total_flight -= chk->send_size;
				net->flight_size -= chk->send_size;
			}
		}
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL);
out:
	if (stcb) {
		SCTP_TCB_UNLOCK(stcb);
	}
}
#endif


void
sctp6_notify(struct sctp_inpcb *inp,
    struct icmp6_hdr *icmph,
    struct sctphdr *sh,
    struct sockaddr *to,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
#if defined (__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
	struct socket *so;

#endif
	/* protection */
	int reason;


	if ((inp == NULL) || (stcb == NULL) || (net == NULL) ||
	    (sh == NULL) || (to == NULL)) {
		if (stcb)
			SCTP_TCB_UNLOCK(stcb);
		return;
	}
	/* First job is to verify the vtag matches what I would send */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag)) {
		SCTP_TCB_UNLOCK(stcb);
		return;
	}
	if (icmph->icmp6_type != ICMP_UNREACH) {
		/* We only care about unreachable */
		SCTP_TCB_UNLOCK(stcb);
		return;
	}
	if ((icmph->icmp6_code == ICMP_UNREACH_NET) ||
	    (icmph->icmp6_code == ICMP_UNREACH_HOST) ||
	    (icmph->icmp6_code == ICMP_UNREACH_NET_UNKNOWN) ||
	    (icmph->icmp6_code == ICMP_UNREACH_HOST_UNKNOWN) ||
	    (icmph->icmp6_code == ICMP_UNREACH_ISOLATED) ||
	    (icmph->icmp6_code == ICMP_UNREACH_NET_PROHIB) ||
	    (icmph->icmp6_code == ICMP_UNREACH_HOST_PROHIB) ||
#ifdef __Panda__
            (icmph->icmp6_code == ICMP_UNREACH_ADMIN)) {
#else
            (icmph->icmp6_code == ICMP_UNREACH_FILTER_PROHIB)) {
#endif

		/*
		 * Hmm reachablity problems we must examine closely. If its
		 * not reachable, we may have lost a network. Or if there is
		 * NO protocol at the other end named SCTP. well we consider
		 * it a OOTB abort.
		 */
		if (net->dest_state & SCTP_ADDR_REACHABLE) {
			/* Ok that destination is NOT reachable */			
			net->dest_state &= ~SCTP_ADDR_REACHABLE;
			net->dest_state &= ~SCTP_ADDR_PF;
			sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
					stcb, SCTP_FAILED_THRESHOLD,
					(void *)net, SCTP_SO_NOT_LOCKED);
		}
		SCTP_TCB_UNLOCK(stcb);
	} else  if ((icmph->icmp6_code == ICMP_UNREACH_PROTOCOL) ||
		    (icmph->icmp6_code == ICMP_UNREACH_PORT)) {
		/*
		 * Here the peer is either playing tricks on us,
		 * including an address that belongs to someone who
		 * does not support SCTP OR was a userland
		 * implementation that shutdown and now is dead. In
		 * either case treat it like a OOTB abort with no
		 * TCB
		 */
		reason = SCTP_PEER_FAULTY;
		sctp_abort_notification(stcb, reason, SCTP_SO_NOT_LOCKED);
#if defined (__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
		so = SCTP_INP_SO(inp);
		atomic_add_int(&stcb->asoc.refcnt, 1);
		SCTP_TCB_UNLOCK(stcb);
		SCTP_SOCKET_LOCK(so, 1);
		SCTP_TCB_LOCK(stcb);
		atomic_subtract_int(&stcb->asoc.refcnt, 1);
#endif
		(void)sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_2);
#if defined (__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
		SCTP_SOCKET_UNLOCK(so, 1);
		/* SCTP_TCB_UNLOCK(stcb); MT: I think this is not needed.*/
#endif
		/* no need to unlock here, since the TCB is gone */
	} else {
		SCTP_TCB_UNLOCK(stcb);
	}
}



#if !defined(__Panda__) && !defined (__Userspace__)
void
sctp6_ctlinput(int cmd, struct sockaddr *pktdst, void *d)
{
	struct sctphdr sh;
	struct ip6ctlparam *ip6cp = NULL;
	uint32_t vrf_id;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
	vrf_id = SCTP_DEFAULT_VRFID;
#endif

#if !defined(__Windows__)
	if (pktdst->sa_family != AF_INET6 ||
	    pktdst->sa_len != sizeof(struct sockaddr_in6))
#else
	if (pktdst->sa_family != AF_INET6)
#endif
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd)) {
		d = NULL;
	} else if (inet6ctlerrmap[cmd] == 0) {
		return;
	}
	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
	} else {
		ip6cp = (struct ip6ctlparam *)NULL;
	}

	if (ip6cp) {
		/*
		 * XXX: We assume that when IPV6 is non NULL, M and OFF are
		 * valid.
		 */
		/* check if we can safely examine src and dst ports */
		struct sctp_inpcb *inp = NULL;
		struct sctp_tcb *stcb = NULL;
		struct sctp_nets *net = NULL;
		struct sockaddr_in6 final;

		if (ip6cp->ip6c_m == NULL)
			return;

		bzero(&sh, sizeof(sh));
		bzero(&final, sizeof(final));
		inp = NULL;
		net = NULL;
		m_copydata(ip6cp->ip6c_m, ip6cp->ip6c_off, sizeof(sh),
		    (caddr_t)&sh);
		ip6cp->ip6c_src->sin6_port = sh.src_port;
#if !defined(__Windows__)
		final.sin6_len = sizeof(final);
#endif
		final.sin6_family = AF_INET6;
#if defined(__FreeBSD__) && __FreeBSD_cc_version < 440000
		final.sin6_addr = *ip6cp->ip6c_finaldst;
#else
		final.sin6_addr = ((struct sockaddr_in6 *)pktdst)->sin6_addr;
#endif				/* __FreeBSD_cc_version */
		final.sin6_port = sh.dest_port;
		stcb = sctp_findassociation_addr_sa((struct sockaddr *)ip6cp->ip6c_src,
		    (struct sockaddr *)&final,
		    &inp, &net, 1, vrf_id);
		/* inp's ref-count increased && stcb locked */
		if (stcb != NULL && inp && (inp->sctp_socket != NULL)) {
			if (cmd == PRC_MSGSIZE) {
				sctp6_notify_mbuf(inp,
				    ip6cp->ip6c_icmp6,
				    &sh,
				    stcb,
				    net);
				/* inp's ref-count reduced && stcb unlocked */
			} else {
				sctp6_notify(inp, ip6cp->ip6c_icmp6, &sh,
				    (struct sockaddr *)&final,
				    stcb, net);
				/* inp's ref-count reduced && stcb unlocked */
			}
		} else {
#if !defined(__Windows__)
			if (PRC_IS_REDIRECT(cmd) && inp) {
				in6_rtchange((struct in6pcb *)inp,
				    inet6ctlerrmap[cmd]);
			}
#endif
			if (inp) {
				/* reduce inp's ref-count */
				SCTP_INP_WLOCK(inp);
				SCTP_INP_DECR_REF(inp);
				SCTP_INP_WUNLOCK(inp);
			}
			if (stcb)
				SCTP_TCB_UNLOCK(stcb);
		}
	}
}
#endif

/*
 * this routine can probably be collasped into the one in sctp_userreq.c
 * since they do the same thing and now we lookup with a sockaddr
 */
#ifdef __FreeBSD__
static int
sctp6_getcred(SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct sockaddr_in6 addrs[2];
	struct sctp_inpcb *inp;
	struct sctp_nets *net;
	struct sctp_tcb *stcb;
	int error;
	uint32_t vrf_id;

#if defined(__FreeBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call(); /* from connectx call? */
#endif

#if defined(__FreeBSD__) && __FreeBSD_version > 602000
	error = priv_check(req->td, PRIV_NETINET_GETCRED);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 500000
	error = suser(req->td);
#else
	error = suser(req->p);
#endif
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs)) {
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}
	if (req->oldlen != sizeof(struct ucred)) {
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);

	stcb = sctp_findassociation_addr_sa(sin6tosa(&addrs[0]),
	    sin6tosa(&addrs[1]),
	    &inp, &net, 1, vrf_id);
	if (stcb == NULL || inp == NULL || inp->sctp_socket == NULL) {
		if ((inp != NULL) && (stcb == NULL)) {
			/* reduce ref-count */
			SCTP_INP_WLOCK(inp);
			SCTP_INP_DECR_REF(inp);
			goto cred_can_cont;
		}
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ENOENT);
		error = ENOENT;
		goto out;
	}
	SCTP_TCB_UNLOCK(stcb);
	/* We use the write lock here, only
	 * since in the error leg we need it.
	 * If we used RLOCK, then we would have
	 * to wlock/decr/unlock/rlock. Which
	 * in theory could create a hole. Better
	 * to use higher wlock.
	 */
	SCTP_INP_WLOCK(inp);
 cred_can_cont:
	error = cr_canseesocket(req->td->td_ucred, inp->sctp_socket);
	if (error) {
		SCTP_INP_WUNLOCK(inp);
		goto out;
	}
	cru2x(inp->sctp_socket->so_cred, &xuc);
	SCTP_INP_WUNLOCK(inp);
	error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
out:
	return (error);
}

SYSCTL_PROC(_net_inet6_sctp6, OID_AUTO, getcred, CTLTYPE_OPAQUE | CTLFLAG_RW,
    0, 0,
    sctp6_getcred, "S,ucred", "Get the ucred of a SCTP6 connection");

#endif

/* This is the same as the sctp_abort() could be made common */
#if (defined(__FreeBSD__) && __FreeBSD_version > 690000) || defined(__Windows__)
static void
#elif defined(__Panda__) || defined(__Userspace__)
int
#else
static int
#endif
sctp6_abort(struct socket *so)
{
	struct sctp_inpcb *inp;
	uint32_t flags;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
#if (defined(__FreeBSD__) && __FreeBSD_version > 690000) || defined(__Windows__)
		return;
#else
		return (EINVAL);
#endif
	}
 sctp_must_try_again:
	flags = inp->sctp_flags;
#ifdef SCTP_LOG_CLOSING
	sctp_log_closing(inp, NULL, 17);
#endif
	if (((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) &&
	    (atomic_cmpset_int(&inp->sctp_flags, flags, (flags | SCTP_PCB_FLAGS_SOCKET_GONE | SCTP_PCB_FLAGS_CLOSE_IP)))) {
#ifdef SCTP_LOG_CLOSING
		sctp_log_closing(inp, NULL, 16);
#endif
		sctp_inpcb_free(inp, SCTP_FREE_SHOULD_USE_ABORT,
				SCTP_CALLED_AFTER_CMPSET_OFCLOSE);
		SOCK_LOCK(so);
		SCTP_SB_CLEAR(so->so_snd);
		/* same for the rcv ones, they are only
		 * here for the accounting/select.
		 */
		SCTP_SB_CLEAR(so->so_rcv);
#if defined(__APPLE__)
		so->so_usecount--;
#else
		/* Now null out the reference, we are completely detached. */
		so->so_pcb = NULL;
#endif
		SOCK_UNLOCK(so);
	} else {
		flags = inp->sctp_flags;
		if ((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
#if (defined(__FreeBSD__) && __FreeBSD_version > 690000) || defined(__Windows__)
	return;
#else
	return (0);
#endif
}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int
sctp6_attach(struct socket *so, int proto SCTP_UNUSED, struct thread *p SCTP_UNUSED)
#elif defined(__Panda__) || defined(__Userspace__)
int
sctp6_attach(struct socket *so, int proto SCTP_UNUSED, uint32_t vrf_id)
#elif defined(__Windows__)
static int
sctp6_attach(struct socket *so, int proto SCTP_UNUSED, PKTHREAD p SCTP_UNUSED)
#else
static int
sctp6_attach(struct socket *so, int proto SCTP_UNUSED, struct proc *p SCTP_UNUSED)
#endif
{
	struct in6pcb *inp6;
	int error;
	struct sctp_inpcb *inp;
#if !defined(__Panda__) && !defined(__Userspace__)
	uint32_t vrf_id = SCTP_DEFAULT_VRFID;
#endif

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != NULL) {
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = SCTP_SORESERVE(so, SCTP_BASE_SYSCTL(sctp_sendspace), SCTP_BASE_SYSCTL(sctp_recvspace));
		if (error)
			return (error);
	}
	error = sctp_inpcb_alloc(so, vrf_id);
	if (error)
		return (error);
	inp = (struct sctp_inpcb *)so->so_pcb;
	SCTP_INP_WLOCK(inp);
	inp->sctp_flags |= SCTP_PCB_FLAGS_BOUND_V6;	/* I'm v6! */
	inp6 = (struct in6pcb *)inp;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
	inp6->inp_vflag |= INP_IPV6;
#else
	inp->inp_vflag |= INP_IPV6;
#endif
#if !defined(__Panda__)
	inp6->in6p_hops = -1;	/* use kernel default */
	inp6->in6p_cksum = -1;	/* just to be sure */
#endif
#ifdef INET
	/*
	 * XXX: ugly!! IPv4 TTL initialization is necessary for an IPv6
	 * socket as well, because the socket may be bound to an IPv6
	 * wildcard address, which may match an IPv4-mapped IPv6 address.
	 */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
	inp6->inp_ip_ttl = MODULE_GLOBAL(ip_defttl);
#else
	inp->inp_ip_ttl = ip_defttl;
#endif
#endif
	/*
	 * Hmm what about the IPSEC stuff that is missing here but in
	 * sctp_attach()?
	 */
	SCTP_INP_WUNLOCK(inp);
	return (0);
}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int
sctp6_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#elif defined(__FreeBSD__) || defined(__APPLE__)
static int
sctp6_bind(struct socket *so, struct sockaddr *addr, struct proc *p)
{
#elif defined(__Panda__) || defined(__Userspace__)
int
sctp6_bind(struct socket *so, struct sockaddr *addr, void * p)
{
#elif defined(__Windows__)
static int
sctp6_bind(struct socket *so, struct sockaddr *addr, PKTHREAD p)
{
#else
static int
sctp6_bind(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = nam ? mtod(nam, struct sockaddr *): NULL;

#endif
	struct sctp_inpcb *inp;
	struct in6pcb *inp6;
	int error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}

#if !defined(__Windows__)
	if (addr) {
		switch (addr->sa_family) {
#ifdef INET
		case AF_INET:
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
			if (addr->sa_len != sizeof(struct sockaddr_in)) {
				SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
				return (EINVAL);
			}
#endif
			break;
#endif
#ifdef INET6
		case AF_INET6:
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
			if (addr->sa_len != sizeof(struct sockaddr_in6)) {
				SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
				return (EINVAL);
			}
#endif
			break;
#endif
		default:
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
#endif
	inp6 = (struct in6pcb *)inp;
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
	inp6->inp_vflag &= ~INP_IPV4;
	inp6->inp_vflag |= INP_IPV6;
#else
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
#endif
	if ((addr != NULL) && (SCTP_IPV6_V6ONLY(inp6) == 0)) {
		switch (addr->sa_family) {
#ifdef INET
		case AF_INET:
			/* binding v4 addr to v6 socket, so reset flags */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
			inp6->inp_vflag |= INP_IPV4;
			inp6->inp_vflag &= ~INP_IPV6;
#else
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
#endif
			break;
#endif
#ifdef INET6
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6_p;

			sin6_p = (struct sockaddr_in6 *)addr;

			if (IN6_IS_ADDR_UNSPECIFIED(&sin6_p->sin6_addr)) {
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
				inp6->inp_vflag |= INP_IPV4;
#else
				inp->inp_vflag |= INP_IPV4;
#endif
			}
#ifdef INET
			if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
				struct sockaddr_in sin;

				in6_sin6_2_sin(&sin, sin6_p);
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__) || defined (__Userspace__)
				inp6->inp_vflag |= INP_IPV4;
				inp6->inp_vflag &= ~INP_IPV6;
#else
				inp->inp_vflag |= INP_IPV4;
				inp->inp_vflag &= ~INP_IPV6;
#endif
				error = sctp_inpcb_bind(so, (struct sockaddr *)&sin, NULL, p);
				return (error);
			}
#endif
			break;
		}
#endif
		default:
			break;
		}
	} else if (addr != NULL) {
		struct sockaddr_in6 *sin6_p;

		/* IPV6_V6ONLY socket */
#ifdef INET
		if (addr->sa_family == AF_INET) {
			/* can't bind v4 addr to v6 only socket! */
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
#endif
		sin6_p = (struct sockaddr_in6 *)addr;

		if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			/* can't bind v4-mapped addrs either! */
			/* NOTE: we don't support SIIT */
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
	error = sctp_inpcb_bind(so, addr, NULL, p);
	return (error);
}


#if (defined(__FreeBSD__) && __FreeBSD_version > 690000) || defined(__Windows__) || defined(__Userspace__)
#if !defined(__Userspace__)
static void
#else
void
#endif
sctp6_close(struct socket *so)
{
	sctp_close(so);
}

/* This could be made common with sctp_detach() since they are identical */
#else

#if !defined(__Panda__)
static
#endif
int
sctp6_detach(struct socket *so)
{
#if defined (__Userspace__)
	sctp_close(so);
	return (0);
#else
	return (sctp_detach(so));
#endif
}

#endif

#if !defined(__Panda__) && !defined(__Userspace__)
static
#endif
int
sctp6_disconnect(struct socket *so)
{
	return(sctp_disconnect(so));
}


int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p);

#else
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p);

#endif

#if !defined(__Panda__) && !defined(__Windows__) && !defined(__Userspace__)
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p)
{
#elif defined(__FreeBSD__) || defined(__APPLE__)
static int
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p)
{
#else
static int
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct mbuf *nam,
    struct mbuf *control, struct proc *p)
{
	struct sockaddr *addr = nam ? mtod(nam, struct sockaddr *): NULL;
#endif
	struct sctp_inpcb *inp;
	struct in6pcb *inp6;

#ifdef INET
	struct sockaddr_in6 *sin6;
#endif /* INET */
	/* No SPL needed since sctp_output does this */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		if (control) {
			SCTP_RELEASE_PKT(control);
			control = NULL;
		}
		SCTP_RELEASE_PKT(m);
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}
	inp6 = (struct in6pcb *)inp;
	/*
	 * For the TCP model we may get a NULL addr, if we are a connected
	 * socket thats ok.
	 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) &&
	    (addr == NULL)) {
		goto connected_type;
	}
	if (addr == NULL) {
		SCTP_RELEASE_PKT(m);
		if (control) {
			SCTP_RELEASE_PKT(control);
			control = NULL;
		}
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EDESTADDRREQ);
		return (EDESTADDRREQ);
	}
#ifdef INET
	sin6 = (struct sockaddr_in6 *)addr;
	if (SCTP_IPV6_V6ONLY(inp6)) {
		/*
		 * if IPV6_V6ONLY flag, we discard datagrams destined to a
		 * v4 addr or v4-mapped addr
		 */
		if (addr->sa_family == AF_INET) {
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if (!MODULE_GLOBAL(ip6_v6only)) {
			struct sockaddr_in sin;

			/* convert v4-mapped into v4 addr and send */
			in6_sin6_2_sin(&sin, sin6);
			return (sctp_sendm(so, flags, m, (struct sockaddr *)&sin,
			    control, p));
		} else {
			/* mapped addresses aren't enabled */
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
#endif				/* INET */
connected_type:
	/* now what about control */
	if (control) {
		if (inp->control) {
			SCTP_PRINTF("huh? control set?\n");
			SCTP_RELEASE_PKT(inp->control);
			inp->control = NULL;
		}
		inp->control = control;
	}
	/* Place the data */
	if (inp->pkt) {
		SCTP_BUF_NEXT(inp->pkt_last) = m;
		inp->pkt_last = m;
	} else {
		inp->pkt_last = inp->pkt = m;
	}
	if (
#if defined(__FreeBSD__) || defined(__APPLE__)
	/* FreeBSD and MacOSX uses a flag passed */
	    ((flags & PRUS_MORETOCOME) == 0)
#else
	    1			/* Open BSD does not have any "more to come"
				 * indication */
#endif
	    ) {
		/*
		 * note with the current version this code will only be used
		 * by OpenBSD, NetBSD and FreeBSD have methods for
		 * re-defining sosend() to use sctp_sosend().  One can
		 * optionaly switch back to this code (by changing back the
		 * defininitions but this is not advisable.
		 */
		int ret;

		ret = sctp_output(inp, inp->pkt, addr, inp->control, p, flags);
		inp->pkt = NULL;
		inp->control = NULL;
		return (ret);
	} else {
		return (0);
	}
}
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int
sctp6_connect(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#elif defined(__FreeBSD__) || defined(__APPLE__)
static int
sctp6_connect(struct socket *so, struct sockaddr *addr, struct proc *p)
{
#elif defined(__Panda__)
int
sctp6_connect(struct socket *so, struct sockaddr *addr, void *p)
{
#elif defined(__Windows__)
static int
sctp6_connect(struct socket *so, struct sockaddr *addr, PKTHREAD p)
{
#elif defined (__Userspace__)
int
sctp6_connect(struct socket *so, struct sockaddr *addr)
{
	void *p = NULL;
#else
static int
sctp6_connect(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
	uint32_t vrf_id;
	int error = 0;
	struct sctp_inpcb *inp;
	struct in6pcb *inp6;
	struct sctp_tcb *stcb;
#ifdef INET
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage ss;
#endif

	inp6 = (struct in6pcb *)so->so_pcb;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ECONNRESET);
		return (ECONNRESET);	/* I made the same as TCP since we are
					 * not setup? */
	}
	if (addr == NULL) {
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}
#if !defined(__Windows__)
	switch (addr->sa_family) {
#ifdef INET
	case AF_INET:
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
		if (addr->sa_len != sizeof(struct sockaddr_in)) {
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
#endif
		break;
#endif
#ifdef INET6
	case AF_INET6:
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
		if (addr->sa_len != sizeof(struct sockaddr_in6)) {
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
#endif
		break;
#endif
	default:
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}
#endif

	vrf_id = inp->def_vrf_id;
	SCTP_ASOC_CREATE_LOCK(inp);
	SCTP_INP_RLOCK(inp);
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		SCTP_INP_RUNLOCK(inp);
		error = sctp6_bind(so, NULL, p);
		if (error) {
			SCTP_ASOC_CREATE_UNLOCK(inp);

			return (error);
		}
		SCTP_INP_RLOCK(inp);
	}
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
		SCTP_INP_RUNLOCK(inp);
		SCTP_ASOC_CREATE_UNLOCK(inp);
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EADDRINUSE);
		return (EADDRINUSE);
	}
#ifdef INET
	sin6 = (struct sockaddr_in6 *)addr;
	if (SCTP_IPV6_V6ONLY(inp6)) {
		/*
		 * if IPV6_V6ONLY flag, ignore connections destined to a v4
		 * addr or v4-mapped addr
		 */
		if (addr->sa_family == AF_INET) {
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if (!MODULE_GLOBAL(ip6_v6only)) {
			/* convert v4-mapped into v4 addr */
			in6_sin6_2_sin((struct sockaddr_in *)&ss, sin6);
			addr = (struct sockaddr *)&ss;
		} else {
			/* mapped addresses aren't enabled */
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
	}
#endif				/* INET */
	/* Now do we connect? */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
		stcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (stcb) {
			SCTP_TCB_UNLOCK(stcb);
		}
		SCTP_INP_RUNLOCK(inp);
	} else {
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_WLOCK(inp);
		SCTP_INP_INCR_REF(inp);
		SCTP_INP_WUNLOCK(inp);
		stcb = sctp_findassociation_ep_addr(&inp, addr, NULL, NULL, NULL);
		if (stcb == NULL) {
			SCTP_INP_WLOCK(inp);
			SCTP_INP_DECR_REF(inp);
			SCTP_INP_WUNLOCK(inp);
		}
	}

	if (stcb != NULL) {
		/* Already have or am bring up an association */
		SCTP_ASOC_CREATE_UNLOCK(inp);
		SCTP_TCB_UNLOCK(stcb);
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EALREADY);
		return (EALREADY);
	}
	/* We are GOOD to go */
	stcb = sctp_aloc_assoc(inp, addr, &error, 0, vrf_id, p);
	SCTP_ASOC_CREATE_UNLOCK(inp);
	if (stcb == NULL) {
		/* Gak! no memory */
		return (error);
	}
	if (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		stcb->sctp_ep->sctp_flags |= SCTP_PCB_FLAGS_CONNECTED;
		/* Set the connected flag so we can queue data */
		soisconnecting(so);
	}
	stcb->asoc.state = SCTP_STATE_COOKIE_WAIT;
	(void)SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_entered);

	/* initialize authentication parameters for the assoc */
	sctp_initialize_auth_params(inp, stcb);

	sctp_send_initiate(inp, stcb, SCTP_SO_LOCKED);
	SCTP_TCB_UNLOCK(stcb);
	return (error);
}

static int
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
sctp6_getaddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in6 *sin6;
#elif defined(__Panda__)
sctp6_getaddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
#else
sctp6_getaddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in6 *sin6 = mtod(nam, struct sockaddr_in6 *);
#endif
	struct sctp_inpcb *inp;
	uint32_t vrf_id;
	struct sctp_ifa *sctp_ifa;

#ifdef SCTP_KAME
	int error;
#endif /* SCTP_KAME */

	/*
	 * Do the malloc first in case it blocks.
	 */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
	SCTP_MALLOC_SONAME(sin6, struct sockaddr_in6 *, sizeof(*sin6));
	if (sin6 == NULL)
		return (ENOMEM);
#elif defined(__Panda__)
	bzero(sin6, sizeof(*sin6));
#else
	SCTP_BUF_LEN(nam) = sizeof(*sin6);
	bzero(sin6, sizeof(*sin6));
#endif
	sin6->sin6_family = AF_INET6;
#if !defined(__Windows__) && !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
	sin6->sin6_len = sizeof(*sin6);
#endif

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		SCTP_FREE_SONAME(sin6);
#endif
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ECONNRESET);
		return (ECONNRESET);
	}
	SCTP_INP_RLOCK(inp);
	sin6->sin6_port = inp->sctp_lport;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* For the bound all case you get back 0 */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
			struct sctp_tcb *stcb;
			struct sockaddr_in6 *sin_a6;
			struct sctp_nets *net;
			int fnd;
			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (stcb == NULL) {
				goto notConn6;
			}
			fnd = 0;
			sin_a6 = NULL;
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				sin_a6 = (struct sockaddr_in6 *)&net->ro._l_addr;
				if (sin_a6 == NULL)
					/* this will make coverity happy */
					continue;

				if (sin_a6->sin6_family == AF_INET6) {
					fnd = 1;
					break;
				}
			}
			if ((!fnd) || (sin_a6 == NULL)) {
				/* punt */
				goto notConn6;
			}
			vrf_id = inp->def_vrf_id;
			sctp_ifa = sctp_source_address_selection(inp, stcb, (sctp_route_t *)&net->ro, net, 0, vrf_id);
			if (sctp_ifa) {
				sin6->sin6_addr = sctp_ifa->address.sin6.sin6_addr;
			}
		} else {
			/* For the bound all case you get back 0 */
	notConn6:
			memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));
		}
	} else {
		/* Take the first IPv6 address in the list */
		struct sctp_laddr *laddr;
		int fnd = 0;

		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->address.sa.sa_family == AF_INET6) {
				struct sockaddr_in6 *sin_a;

				sin_a = (struct sockaddr_in6 *)&laddr->ifa->address.sin6;
				sin6->sin6_addr = sin_a->sin6_addr;
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
			SCTP_FREE_SONAME(sin6);
#endif
			SCTP_INP_RUNLOCK(inp);
			SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ENOENT);
			return (ENOENT);
		}
	}
	SCTP_INP_RUNLOCK(inp);
	/* Scoping things for v6 */
#ifdef SCTP_EMBEDDED_V6_SCOPE
#ifdef SCTP_KAME
	if ((error = sa6_recoverscope(sin6)) != 0) {
		SCTP_FREE_SONAME(sin6);
		return (error);
	}
#else
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		/* skip ifp check below */
		in6_recoverscope(sin6, &sin6->sin6_addr, NULL);
	else
		sin6->sin6_scope_id = 0;	/* XXX */
#endif /* SCTP_KAME */
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
	(*addr) = (struct sockaddr *)sin6;
#endif
	return (0);
}

static int
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
sctp6_peeraddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in6 *sin6;
#elif defined(__Panda__)
sctp6_peeraddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
#else
sctp6_peeraddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in6 *sin6 = mtod(nam, struct sockaddr_in6 *);
#endif
	int fnd;
	struct sockaddr_in6 *sin_a6;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_nets *net;
#ifdef SCTP_KAME
	int error;
#endif

	/* Do the malloc first in case it blocks. */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
	SCTP_MALLOC_SONAME(sin6, struct sockaddr_in6 *, sizeof *sin6);
	if (sin6 == NULL)
		return (ENOMEM);
#elif defined(__Panda__)
	memset(sin6, 0, sizeof(*sin6));
#else
	SCTP_BUF_LEN(nam) = sizeof(*sin6);
	memset(sin6, 0, sizeof(*sin6));
#endif
	sin6->sin6_family = AF_INET6;
#if !defined(__Windows__) && !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
	sin6->sin6_len = sizeof(*sin6);
#endif

	inp = (struct sctp_inpcb *)so->so_pcb;
	if ((inp == NULL) ||
	    ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0)) {
		/* UDP type and listeners will drop out here */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		SCTP_FREE_SONAME(sin6);
#endif
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ENOTCONN);
		return (ENOTCONN);
	}
	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (stcb) {
		SCTP_TCB_LOCK(stcb);
	}
	SCTP_INP_RUNLOCK(inp);
	if (stcb == NULL) {
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		SCTP_FREE_SONAME(sin6);
#endif
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ECONNRESET);
		return (ECONNRESET);
	}
	fnd = 0;
	TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
		sin_a6 = (struct sockaddr_in6 *)&net->ro._l_addr;
		if (sin_a6->sin6_family == AF_INET6) {
			fnd = 1;
			sin6->sin6_port = stcb->rport;
			sin6->sin6_addr = sin_a6->sin6_addr;
			break;
		}
	}
	SCTP_TCB_UNLOCK(stcb);
	if (!fnd) {
		/* No IPv4 address */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		SCTP_FREE_SONAME(sin6);
#endif
		SCTP_LTRACE_ERR_RET(inp, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, ENOENT);
		return (ENOENT);
	}
#ifdef SCTP_EMBEDDED_V6_SCOPE
#ifdef SCTP_KAME
	if ((error = sa6_recoverscope(sin6)) != 0)
		return (error);
#else
	in6_recoverscope(sin6, &sin6->sin6_addr, NULL);
#endif /* SCTP_KAME */
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
	*addr = (struct sockaddr *)sin6;
#endif
	return (0);
}

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
static int
sctp6_in6getaddr(struct socket *so, struct sockaddr **nam)
{
#ifdef INET
	struct sockaddr *addr;
#endif
#elif defined(__Panda__)
int
sctp6_in6getaddr(struct socket *so, struct sockaddr *nam, uint32_t *namelen)
{
	struct sockaddr *addr = nam;
#elif defined(__Userspace__)
int
sctp6_in6getaddr(struct socket *so, struct mbuf *nam)
{
#if defined(INET)
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
#else
static int
sctp6_in6getaddr(struct socket *so, struct mbuf *nam)
{
#if defined(INET)
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
#endif
	struct in6pcb *inp6 = sotoin6pcb(so);
	int error;

	if (inp6 == NULL) {
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}

	/* allow v6 addresses precedence */
	error = sctp6_getaddr(so, nam);
#ifdef INET
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_ingetaddr(so, nam);
		if (error) {
			return (error);
		}
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		addr = *nam;
#endif
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (SCTP_IPV6_V6ONLY(inp6)) {
			struct sockaddr_in6 sin6;

			in6_sin_2_v4mapsin6((struct sockaddr_in *)addr, &sin6);
			memcpy(addr, &sin6, sizeof(struct sockaddr_in6));
		}
	}
#endif
#if defined(__Panda__)
	*namelen = nam->sa_len;
#endif
	return (error);
}


#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
static int
sctp6_getpeeraddr(struct socket *so, struct sockaddr **nam)
{
#ifdef INET
	struct sockaddr *addr;
#endif
#elif defined(__Panda__)
int
sctp6_getpeeraddr(struct socket *so, struct sockaddr *nam, uint32_t *namelen)
{
	struct sockaddr *addr = (struct sockaddr *)nam;
#elif defined(__Userspace__)
int
sctp6_getpeeraddr(struct socket *so, struct mbuf *nam)
{
#if defined(INET)
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
#else
static
int
sctp6_getpeeraddr(struct socket *so, struct mbuf *nam)
{
#if defined(INET)
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif

#endif
	struct in6pcb *inp6 = sotoin6pcb(so);
	int error;

	if (inp6 == NULL) {
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
		return (EINVAL);
	}

	/* allow v6 addresses precedence */
	error = sctp6_peeraddr(so, nam);
#ifdef INET
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_peeraddr(so, nam);
		if (error) {
			return (error);
		}
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
		addr = *nam;
#endif
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (SCTP_IPV6_V6ONLY(inp6)) {
			struct sockaddr_in6 sin6;

			in6_sin_2_v4mapsin6((struct sockaddr_in *)addr, &sin6);
			memcpy(addr, &sin6, sizeof(struct sockaddr_in6));
		}
	}
#endif
#if defined(__Panda__)
	*namelen = nam->sa_len;
#endif
	return (error);
}

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
struct pr_usrreqs sctp6_usrreqs = {
#if __FreeBSD_version >= 600000
	.pru_abort = sctp6_abort,
	.pru_accept = sctp_accept,
	.pru_attach = sctp6_attach,
	.pru_bind = sctp6_bind,
	.pru_connect = sctp6_connect,
	.pru_control = in6_control,
#if __FreeBSD_version >= 690000
	.pru_close = sctp6_close,
	.pru_detach = sctp6_close,
	.pru_sopoll = sopoll_generic,
	.pru_flush = sctp_flush,	
#else
	.pru_detach = sctp6_detach,
	.pru_sopoll = sopoll,
#endif
	.pru_disconnect = sctp6_disconnect,
	.pru_listen = sctp_listen,
	.pru_peeraddr = sctp6_getpeeraddr,
	.pru_send = sctp6_send,
	.pru_shutdown = sctp_shutdown,
	.pru_sockaddr = sctp6_in6getaddr,
	.pru_sosend = sctp_sosend,
	.pru_soreceive = sctp_soreceive
#else
	sctp6_abort,
	sctp_accept,
	sctp6_attach,
	sctp6_bind,
	sctp6_connect,
	pru_connect2_notsupp,
#if defined(__Windows__)
	NULL,
	NULL,
#else
	in6_control,
	sctp6_detach,
#endif
	sctp6_disconnect,
	sctp_listen,
	sctp6_getpeeraddr,
	NULL,
	pru_rcvoob_notsupp,
#if defined(__Windows__)
	NULL,
#else
	sctp6_send,
#endif
	pru_sense_null,
	sctp_shutdown,
#if defined(__Windows__)
	sctp_flush,
#endif
	sctp6_in6getaddr,
	sctp_sosend,
	sctp_soreceive,
#if !defined(__Windows__)
 	sopoll
#else
	sopoll_generic,
	NULL,
	sctp6_close
#endif
#endif
};

#elif !defined(__Panda__) && !defined(__Userspace__)
int
sctp6_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
{
	int s;
	int error = 0;
	int family;
	uint32_t vrf_id;
	family = so->so_proto->pr_domain->dom_family;

	if (req == PRU_CONTROL) {
		switch (family) {
		case PF_INET:
			error = in_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control
			    );
#ifdef INET6
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, p);
#endif
		default:
			SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EAFNOSUPPORT);
			error = EAFNOSUPPORT;
		}
		return (error);
	}
	switch (req) {
	case PRU_ATTACH:
		error = sctp6_attach(so, family, p);
		break;
	case PRU_DETACH:
		error = sctp6_detach(so);
		break;
	case PRU_BIND:
		if (nam == NULL) {
			SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
		error = sctp6_bind(so, nam, p);
		break;
	case PRU_LISTEN:
		error = sctp_listen(so, p);
		break;
	case PRU_CONNECT:
		if (nam == NULL) {
			SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
		error = sctp6_connect(so, nam, p);
		break;
	case PRU_DISCONNECT:
		error = sctp6_disconnect(so);
		break;
	case PRU_ACCEPT:
		if (nam == NULL) {
			SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EINVAL);
			return (EINVAL);
		}
		error = sctp_accept(so, nam);
		break;
	case PRU_SHUTDOWN:
		error = sctp_shutdown(so);
		break;

	case PRU_RCVD:
		/*
		 * For OpenBSD and NetBSD, this is real ugly. The (mbuf *)
		 * nam that is passed (by soreceive()) is the int flags cast
		 * as a (mbuf *) yuck!
		 */
		error = sctp_usr_recvd(so, (int)((long)nam));
		break;

	case PRU_SEND:
		/* Flags are ignored */
		error = sctp6_send(so, 0, m, nam, control, p);
		break;
	case PRU_ABORT:
		error = sctp6_abort(so);
		break;

	case PRU_SENSE:
		error = 0;
		break;
	case PRU_RCVOOB:
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EAFNOSUPPORT);
		error = EAFNOSUPPORT;
		break;
	case PRU_SENDOOB:
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP6_USRREQ, EAFNOSUPPORT);
		error = EAFNOSUPPORT;
		break;
	case PRU_PEERADDR:
		error = sctp6_getpeeraddr(so, nam);
		break;
	case PRU_SOCKADDR:
		error = sctp6_in6getaddr(so, nam);
		break;
	case PRU_SLOWTIMO:
		error = 0;
		break;
	default:
		break;
	}
	return (error);
}
#endif
