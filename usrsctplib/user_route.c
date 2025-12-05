/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1980, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#if defined(__Userspace_os_Windows)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <netinet/sctp_os.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>

#include "user_route.h"
#include "user_environment.h"
#include "user_atomic.h"

void
rtalloc(struct sctp_route *ro, uint32_t vrf_id)
{
	struct sctp_vrf *vrf;
	struct sctp_ifn *ifn;
	SOCKADDR_INET dest, best_src;
	MIB_IPFORWARD_ROW2 best_route;
	if (ro->ro_rt != NULL) {
		ro->ro_rt->rt_refcnt++;
		return;
	}

	ro->ro_rt = (struct sctp_rtentry *) malloc(sizeof(struct sctp_rtentry));
	if (ro->ro_rt == NULL)
		return;

	/* initialize */
	memset(ro->ro_rt, 0, sizeof(struct sctp_rtentry));
	ro->ro_rt->rt_refcnt = 1;

	/* set MTU */
	/* TODO set this based on the ro->ro_dst, looking up MTU with routing socket */
#if 0
	if (userspace_rawroute == -1) {
		userspace_rawroute = socket(AF_ROUTE, SOCK_RAW, 0);
		if (userspace_rawroute == -1)
			return;
	}
#endif
	ro->ro_rt->rt_rmx.rmx_mtu = 1500; /* FIXME temporary solution */

	/* TODO enable the ability to obtain interface index of route for
	 *  SCTP_GET_IF_INDEX_FROM_ROUTE macro.
	 */
#if defined(__Userspace_os_Windows)
	vrf = sctp_find_vrf(vrf_id);
	LIST_FOREACH(ifn, &vrf->ifnlist, next_ifn) {
		if (ro->ro_dst.sa_family == AF_INET) {
			memcpy(&dest.Ipv4, &ro->ro_dst, sizeof(struct sockaddr_in));
			dest.si_family = AF_INET;
		} else if (ro->ro_dst.sa_family == AF_INET6) {
			memcpy(&dest.Ipv6, &ro->ro_dst, sizeof(struct sockaddr_in6));
			dest.si_family = AF_INET6;
		} else {
			continue;
		}
		if (GetBestRoute2(NULL, ifn->ifn_index, NULL, &dest, 0, &best_route, &best_src) == NO_ERROR) {
			atomic_add_int(&ifn->refcount, 1);
			ro->ro_rt->rt_ifp = (struct ifnet *)ifn;
			break;
		}
	}
#endif
}

void
rtfree(struct sctp_rtentry *rt)
{
	if (rt == NULL) {
		return;
	}
	if (--rt->rt_refcnt > 0) {
		return;
	}
    if (rt->rt_ifp != NULL) {
		atomic_add_int(&((struct sctp_ifn *)rt->rt_ifp)->refcount, -1);
    }
	free(rt);
}
#endif