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

#ifndef _NETINET_SCTP_IN_PORT_H_
#define _NETINET_SCTP_IN_PORT_H_

#if defined(SCTP_USE_LWIP)
/* Standard well-known ports.  */
enum
  {
    IPPORT_ECHO = 7,           /* Echo service.  */
    IPPORT_DISCARD = 9,                /* Discard transmissions service.  */
    IPPORT_SYSTAT = 11,                /* System status service.  */
    IPPORT_DAYTIME = 13,       /* Time of day service.  */
    IPPORT_NETSTAT = 15,       /* Network status service.  */
    IPPORT_FTP = 21,           /* File Transfer Protocol.  */
    IPPORT_TELNET = 23,                /* Telnet protocol.  */
    IPPORT_SMTP = 25,          /* Simple Mail Transfer Protocol.  */
    IPPORT_TIMESERVER = 37,    /* Timeserver service.  */
    IPPORT_NAMESERVER = 42,    /* Domain Name Service.  */
    IPPORT_WHOIS = 43,         /* Internet Whois service.  */
    IPPORT_MTP = 57,

    IPPORT_TFTP = 69,          /* Trivial File Transfer Protocol.  */
    IPPORT_RJE = 77,
    IPPORT_FINGER = 79,                /* Finger service.  */
    IPPORT_TTYLINK = 87,
    IPPORT_SUPDUP = 95,                /* SUPDUP protocol.  */


    IPPORT_EXECSERVER = 512,   /* execd service.  */
    IPPORT_LOGINSERVER = 513,  /* rlogind service.  */
    IPPORT_CMDSERVER = 514,
    IPPORT_EFSSERVER = 520,

    /* UDP ports.  */
    IPPORT_BIFFUDP = 512,
    IPPORT_WHOSERVER = 513,
    IPPORT_ROUTESERVER = 520,

    /* Ports less than this value are reserved for privileged processes.  */
    IPPORT_RESERVED = 1024,

    /* Ports greater this value are reserved for (non-privileged) servers.  */
    IPPORT_USERRESERVED = 5000
  };

#define        IP_HDRINCL      3       /* int; Header is included with data.  */
#endif
#endif//!< _NETINET_SCTP_IN_PORT_H_
