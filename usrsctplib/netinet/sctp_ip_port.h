/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
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

#if defined(__FreeBSD__) && !defined(__Userspace__)
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/netinet/sctp_timer.h 359195 2020-03-21 16:12:19Z tuexen $");
#endif

#ifndef _NETINET_SCTP_IP_PORT_H_
#define _NETINET_SCTP_IP_PORT_H_

#if !defined(SCTP_USE_LWIP)
#include <netinet/ip.h>
#define STRUCT_IP_HDR struct ip
//#define GET_IP_VERSION(ip) ((struct ip_hdr*)(ip))->ip_v
//#define GET_IP_HDR_LEN(ip) ((struct ip_hdr*)(ip))->ip_hl
#define GET_IP_TOS(ip) ((struct ip*)(ip))->ip_tos
#define GET_IP_LEN(ip) ((struct ip*)ip)->ip_len
#define GET_IP_ID(ip) ((struct ip*)ip)->ip_id
#define GET_IP_OFFSET(ip) ((struct ip*)ip)->ip_off
#define GET_IP_TTL(ip) ((struct ip*)ip)->ip_ttl
#define GET_IP_PROTO(ip) ((struct ip*)ip)->ip_p
#define GET_IP_CHKSUM(ip) ((struct ip*)ip)->ip_sum
#define GET_IP_SRC(ip) ((struct ip*)ip)->ip_src
#define GET_IP_DEST(ip) ((struct ip*)ip)->ip_dst
#define GET_IP_SRC_ADDR(ip) ((struct ip*)ip)->ip_src.s_addr
#define GET_IP_DEST_ADDR(ip) ((struct ip*)ip)->ip_dst.s_addr

#define GET_IP_VERSION_VAL(ip) ((struct ip_hdr*)(ip))->ip_v
#define GET_IP_HDR_LEN_VAL(ip) ((struct ip_hdr*)(ip))->ip_hl

#define SET_IP_VHL(hdr, v, hl) do{\
                                    (hdr)->ip_v = v;\
                                    (hdr)->ip_hl = hl;\
                                }while(0)
#else
#include "lwip/ip.h"
#define STRUCT_IP_HDR struct ip_hdr
//#define GET_IP_VERSION(ip) ((struct ip_hdr*)(ip))->_v_hl
//#define GET_IP_HDR_LEN(ip) ((struct ip_hdr*)(ip))->_v_hl
#define GET_IP_TOS(ip) IPH_TOS(ip)//((struct ip_hdr*)(ip))->_tos
#define GET_IP_LEN(ip) IPH_LEN(ip)//((struct ip_hdr*)ip)->_len
#define GET_IP_ID(ip) IPH_ID(ip)//((struct ip_hdr*)ip)->_id
#define GET_IP_OFFSET(ip) IPH_OFFSET(ip)//((struct ip_hdr*)ip)->_offset
#define GET_IP_TTL(ip) IPH_TTL(ip)//((struct ip_hdr*)ip)->_ttl
#define GET_IP_PROTO(ip) IPH_PROTO(ip)//((struct ip_hdr*)ip)->_proto
#define GET_IP_CHKSUM(ip) IPH_CHKSUM(ip)//((struct ip_hdr*)ip)->_chksum
#define GET_IP_SRC(ip) ((struct ip_hdr*)ip)->src
#define GET_IP_DEST(ip) ((struct ip_hdr*)ip)->dest
#define GET_IP_SRC_ADDR(ip) ((struct ip_hdr*)ip)->src.addr
#define GET_IP_DEST_ADDR(ip) ((struct ip_hdr*)ip)->dest.addr


#define GET_IP_VERSION_VAL(ip) IPH_V(ip)
#define GET_IP_HDR_LEN_VAL(ip) IPH_HL(ip)

#define SET_IP_VHL(hdr, v, hl) IPH_VHL_SET(hdr, v, hl)
#endif

#endif//!< _NETINET_SCTP_UDP_PORT_H_
