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

#ifndef _NETINET_SCTP_UDP_PORT_H_
#define _NETINET_SCTP_UDP_PORT_H_

#if !defined(_WIN32)
#if defined(INET) || defined(INET6)
#if !defined(SCTP_USE_LWIP)
#include <netinet/udp.h>

#define STRUCT_UDP_HDR struct udphdr
#define GET_UDP_SRC(udp) ((struct udphdr*)udp)->source
#define GET_UDP_DEST(udp) ((struct udphdr*)udp)->dest
#define GET_UDP_LEN(udp) ((struct udphdr*)udp)->len
#define GET_UDP_CHKSUM(udp) ((struct udphdr*)udp)->check

#else
#include "lwip/udp.h"
#define STRUCT_UDP_HDR struct udp_hdr
#define GET_UDP_SRC(udp) ((struct udp_hdr*)udp)->src
#define GET_UDP_DEST(udp) ((struct udp_hdr*)udp)->dest
#define GET_UDP_LEN(udp) ((struct udp_hdr*)udp)->len
#define GET_UDP_CHKSUM(udp) ((struct udp_hdr*)udp)->chksum

// #TBD
#define UIO_MAXIOV 1024
#define ERESTART        85  /* Interrupted system call should be restarted */

#endif
#endif
#include <arpa/inet.h>
#else
#include <user_socketvar.h>
#endif


#endif//!< _NETINET_SCTP_UDP_PORT_H_
