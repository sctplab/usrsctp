#include <sys/types.h>
#if !defined(__Userspace_os_Windows)
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#if !defined(__Userspace_os_FreeBSD)
#include <sys/uio.h>
#else
#include <user_ip6_var.h>
#endif
#endif
#include <netinet/sctp_os.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#if defined(__Userspace_os_Linux)
#include <linux/netlink.h>
#include <linux/if_addr.h>
#endif
/* extern __Userspace__ variable in user_recv_thread.h */
int userspace_rawsctp = -1; /* needs to be declared = -1 */
int userspace_udpsctp = -1;
#if defined(INET6)
int userspace_rawsctp6 = -1;
int userspace_udpsctp6 = -1;
#endif
int userspace_route = -1;

/* local macros and datatypes used to get IP addresses system independently */
#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
# define dstaddr(x) (CMSG_DATA(x))
#elif defined IP_PKTINFO
# define DSTADDR_SOCKOPT IP_PKTINFO
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#else
# error "can't determine socket option to use to get UDP IP"
#endif

void recv_thread_destroy(void);
#define MAXLEN_MBUF_CHAIN 32 /* What should this value be? */
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))
#if !defined(__Userspace_os_Windows)
#define NEXT_SA(ap) ap = (struct sockaddr *) \
	((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (uint32_t)) : sizeof(uint32_t)))
#endif

#if !defined(__Userspace_os_Windows) && !defined(__Userspace_os_Linux)
static void
sctp_get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			NEXT_SA(sa);
		} else {
			rti_info[i] = NULL;
		}
	}
}
#endif

static void
sctp_handle_ifamsg(unsigned char type, unsigned short index, struct sockaddr *sa)
{
	int rc;
	struct ifaddrs *ifa, *found_ifa = NULL;

	/* handle only the types we want */
	if ((type != RTM_NEWADDR) && (type != RTM_DELADDR)) {
		return;
	}

	rc = getifaddrs(&g_interfaces);
	if (rc != 0) {
		printf("getifaddrs failed\n");
		return;
	}
	for (ifa = g_interfaces; ifa; ifa = ifa->ifa_next) {
		if (index == if_nametoindex(ifa->ifa_name)) {
			found_ifa = ifa;
			break;
		}
	}
	if (found_ifa == NULL) {
		/* TSNH */
		printf("ifa not found?!\n");
		return;
	}

	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
		ifa->ifa_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
		memcpy(ifa->ifa_addr, sa, sizeof(struct sockaddr_in));
		break;
#endif
#ifdef INET6
	case AF_INET6:
		ifa->ifa_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
		memcpy(ifa->ifa_addr, sa, sizeof(struct sockaddr_in6));
		break;
#endif
	default:
		printf("Address family not supported\n");
	}

	/* relay the appropriate address change to the base code */
	if (type == RTM_NEWADDR) {
		(void)sctp_add_addr_to_vrf(SCTP_DEFAULT_VRFID, ifa, if_nametoindex(ifa->ifa_name),
		                           0,
		                           ifa->ifa_name,
		                           (void *)ifa,
		                           ifa->ifa_addr,
		                           0,
		                           1);
	} else {
		sctp_del_addr_from_vrf(SCTP_DEFAULT_VRFID, ifa->ifa_addr,
		                       if_nametoindex(ifa->ifa_name),
		                       ifa->ifa_name);
	}
}

#if !defined(__Userspace_os_Windows)
#if !defined(__Userspace_os_Linux)
static void *
recv_function_route(void *arg)
{
	ssize_t ret;
	struct ifa_msghdr *ifa;
	char rt_buffer[1024];
	struct sockaddr *sa, *rti_info[RTAX_MAX];

	while(1) {
		bzero(rt_buffer, sizeof(rt_buffer));
		ret = recv(userspace_route, rt_buffer, sizeof(rt_buffer), 0);

		if (ret > 0) {
			ifa = (struct ifa_msghdr *) rt_buffer;
			if (ifa->ifam_type != RTM_DELADDR && ifa->ifam_type != RTM_NEWADDR) {
				continue;
			}
			sa = (struct sockaddr *) (ifa + 1);
			sctp_get_rtaddrs(ifa->ifam_addrs, sa, rti_info);
			switch (ifa->ifam_type) {
			case RTM_DELADDR:
			case RTM_NEWADDR:
				sctp_handle_ifamsg(ifa->ifam_type, ifa->ifam_index, rti_info[RTAX_IFA]);
				break;
			default:
				/* ignore this routing event */
				break;
			}
		}
	}
	return NULL;
}
#else /*Userspace_os_Linux*/
static void *
recv_function_route(void *arg)
{
	int fd;
	int len;
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct sockaddr_nl sanl;
	struct ifaddrmsg *rtmsg;
	struct rtattr *rtatp; 
	struct in_addr *inp;
#ifdef INET
	struct sockaddr_in *sa;
#endif
#ifdef INET6
	struct sockaddr_in6 *sa6;
#endif
	memset(&sanl, 0, sizeof(sanl));
	sanl.nl_family = AF_NETLINK;
	sanl.nl_groups = RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_IFADDR;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	bind(fd, (struct sockaddr *) &sanl, sizeof(sanl));

	while (1) {
		memset(&msg, 0, sizeof(struct msghdr));
		msg.msg_name = (void *)&sanl;
		msg.msg_namelen = sizeof(sanl);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		len = recvmsg(fd, &msg, 0);

		for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len);
			nh = NLMSG_NEXT (nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE)
				return NULL;

			if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
				rtmsg = (struct ifaddrmsg *)NLMSG_DATA(nh);
				rtatp = (struct rtattr *)IFA_RTA(rtmsg);
				if(rtatp->rta_type == IFA_ADDRESS) {
					inp = (struct in_addr *)RTA_DATA(rtatp);
					switch (rtmsg->ifa_family) {
#ifdef INET
					case AF_INET:
						sa = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
						sa->sin_family = rtmsg->ifa_family;
						sa->sin_port = 0;
						memcpy(&sa->sin_addr, inp, sizeof(struct in_addr));
						sctp_handle_ifamsg(nh->nlmsg_type, rtmsg->ifa_index, (struct sockaddr *)sa);
						break;
#endif
#ifdef INET6
					case AF_INET6:
						sa6 = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
						sa6->sin6_family = rtmsg->ifa_family;
						sa6->sin6_port = 0;
						memcpy(&sa6->sin6_addr, inp, sizeof(struct in6_addr));
						sctp_handle_ifamsg(nh->nlmsg_type, rtmsg->ifa_index, (struct sockaddr *)sa6);
						break;
#endif
					default:
						printf("Address family not supported\n");
					}
				}
			}
		}
	}
	pthread_exit(NULL);
	return NULL;
}
#endif
#endif

/* need ref to this for destroy... */
struct mbuf **recvmbuf;

static void *
recv_function_raw(void *arg)
{
#if !defined(__Userspace_os_Windows)
	struct iovec recv_iovec[MAXLEN_MBUF_CHAIN];
	int iovcnt = MAXLEN_MBUF_CHAIN;
#else
	WSABUF recv_iovec[MAXLEN_MBUF_CHAIN];
	int nResult, m_ErrorCode;
	DWORD flags;
	struct sockaddr_in from;
	int fromlen;
#endif

	/*Initially the entire set of mbufs is to be allocated.
	  to_fill indicates this amount. */
	int to_fill = MAXLEN_MBUF_CHAIN;
	/* iovlen is the size of each mbuf in the chain */
	int i, n, ncounter = 0;
	int iovlen = MCLBYTES;
	int want_ext = (iovlen > MLEN)? 1 : 0;
	int want_header = 0;

	recvmbuf = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);

	while (1) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			recvmbuf[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
#if !defined(__Userspace_os_Windows)
			recv_iovec[i].iov_base = (caddr_t)recvmbuf[i]->m_data;
			recv_iovec[i].iov_len = iovlen;
#else
			recv_iovec[i].buf = (caddr_t)recvmbuf[i]->m_data;
			recv_iovec[i].len = iovlen;
#endif
		}
		to_fill = 0;
#if defined(__Userspace_os_Windows)
		flags = 0;
		ncounter = 0;
		fromlen = sizeof(struct sockaddr_in);
		bzero((void *)&from, sizeof(struct sockaddr_in));

		nResult = WSARecvFrom(userspace_rawsctp, recv_iovec, MAXLEN_MBUF_CHAIN, (LPDWORD)&ncounter, (LPDWORD)&flags, (struct sockaddr*)&from, &fromlen, NULL, NULL);
		if (nResult != 0) {
			m_ErrorCode = WSAGetLastError();
			printf("error: %d\n", m_ErrorCode);
		}
		n = ncounter;
#else
		ncounter = n = readv(userspace_rawsctp, recv_iovec, iovcnt);
		if (n < 0) {
			continue;
		}
#endif
		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(recvmbuf[0]) = n; /* length of total packet */
		
		if (n <= iovlen) {
			SCTP_BUF_LEN(recvmbuf[0]) = n;
			(to_fill)++;
		} else {
			i = 0;
			SCTP_BUF_LEN(recvmbuf[0]) = iovlen;

			ncounter -= iovlen;
			(to_fill)++;
			do {
				recvmbuf[i]->m_next = recvmbuf[i+1];
				SCTP_BUF_LEN(recvmbuf[i]->m_next) = min(ncounter, iovlen);
				i++;
				ncounter -= iovlen;
				(to_fill)++;
			} while (ncounter > 0);
		}
		assert(to_fill <= MAXLEN_MBUF_CHAIN);
		SCTPDBG(SCTP_DEBUG_INPUT1, "%s: Received %d bytes.", __func__, n);
		SCTPDBG(SCTP_DEBUG_INPUT1, " - calling sctp_input with off=%d\n", (int)sizeof(struct ip));
		
		/* process incoming data */
		/* sctp_input frees this mbuf. */
		sctp_input_with_port(recvmbuf[0], sizeof(struct ip), 0);
	}
	return NULL;
}

#if defined(INET6)
struct mbuf **recvmbuf6;

static void *
recv_function_raw6(void *arg)
{
#if !defined(__Userspace_os_Windows)
	struct iovec recv_iovec[MAXLEN_MBUF_CHAIN];
	struct msghdr msg;
	struct cmsghdr *cmsgptr;
	char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
#else
	WSABUF recv_iovec[MAXLEN_MBUF_CHAIN];
	int nResult, m_ErrorCode;
	DWORD flags;
	struct sockaddr_in6 from;
	int fromlen;
	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	LPFN_WSARECVMSG WSARecvMsg;
	WSACMSGHDR *pCMsgHdr;
	WSAMSG win_msg;
	char ControlBuffer[1024];
#endif
	struct mbuf *ip6_m;
	struct ip6_hdr *ip6;
	struct sockaddr_in6 src, dst;
	int offset;

	/*Initially the entire set of mbufs is to be allocated.
	  to_fill indicates this amount. */
	int to_fill = MAXLEN_MBUF_CHAIN;
	/* iovlen is the size of each mbuf in the chain */
	int i, n, ncounter = 0;
	int iovlen = MCLBYTES;
	int want_ext = (iovlen > MLEN)? 1 : 0;
	int want_header = 0;

	recvmbuf6 = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);

	for (;;) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			recvmbuf6[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
#if !defined(__Userspace_os_Windows)
			recv_iovec[i].iov_base = (caddr_t)recvmbuf6[i]->m_data;
			recv_iovec[i].iov_len = iovlen;
#else
			recv_iovec[i].buf = (caddr_t)recvmbuf6[i]->m_data;
			recv_iovec[i].len = iovlen;
#endif
		}
		to_fill = 0;
#if defined(__Userspace_os_Windows)
		flags = 0;
		ncounter = 0;
		fromlen = sizeof(struct sockaddr_in6);
		bzero((void *)&from, sizeof(struct sockaddr_in6));
		nResult = WSAIoctl(userspace_rawsctp6, SIO_GET_EXTENSION_FUNCTION_POINTER,
		                   &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
		                   &WSARecvMsg, sizeof WSARecvMsg,
		                   &ncounter, NULL, NULL);
		if (nResult == SOCKET_ERROR) {
			m_ErrorCode = WSAGetLastError();
			WSARecvMsg = NULL;
		}
		win_msg.name = (void *)&src;
		win_msg.namelen = sizeof(struct sockaddr_in6);
		win_msg.lpBuffers = recv_iovec;
		win_msg.dwBufferCount = MAXLEN_MBUF_CHAIN;
		win_msg.Control.len = sizeof ControlBuffer;
		win_msg.Control.buf = ControlBuffer;
		win_msg.dwFlags = 0;
		nResult = WSARecvMsg(userspace_rawsctp6, &win_msg, &ncounter, NULL, NULL);
		if (nResult != 0) {
			m_ErrorCode = WSAGetLastError();
		}
		n = ncounter;
#else
		bzero((void *)&msg, sizeof(struct msghdr));
		bzero((void *)&src, sizeof(struct sockaddr_in6));
		bzero((void *)&dst, sizeof(struct sockaddr_in6));
		bzero((void *)cmsgbuf, CMSG_SPACE(sizeof (struct in6_pktinfo)));
		msg.msg_name = (void *)&src;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		msg.msg_iov = recv_iovec;
		msg.msg_iovlen = MAXLEN_MBUF_CHAIN;
		msg.msg_control = (void *)cmsgbuf;
		msg.msg_controllen = (socklen_t)CMSG_LEN(sizeof (struct in6_pktinfo));
		msg.msg_flags = 0;

		ncounter = n = recvmsg(userspace_rawsctp6, &msg, 0);
		if (n < 0) {
			continue;
		}
#endif
		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(recvmbuf6[0]) = n; /* length of total packet */

		if (n <= iovlen) {
			SCTP_BUF_LEN(recvmbuf6[0]) = n;
			(to_fill)++;
		} else {
			i = 0;
			SCTP_BUF_LEN(recvmbuf6[0]) = iovlen;

			ncounter -= iovlen;
			(to_fill)++;
			do {
				recvmbuf6[i]->m_next = recvmbuf6[i+1];
				SCTP_BUF_LEN(recvmbuf6[i]->m_next) = min(ncounter, iovlen);
				i++;
				ncounter -= iovlen;
				(to_fill)++;
			} while (ncounter > 0);
		}
		assert(to_fill <= MAXLEN_MBUF_CHAIN);

#if !defined(__Userspace_os_Windows)
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
			if ((cmsgptr->cmsg_level == IPPROTO_IPV6) && (cmsgptr->cmsg_type == IPV6_PKTINFO)) {
				memcpy((void *)&dst.sin6_addr, (const void *) (&((struct in6_pktinfo *)CMSG_DATA(cmsgptr))->ipi6_addr), sizeof(struct in6_addr));
			}
		}
#else
		for (pCMsgHdr = WSA_CMSG_FIRSTHDR(&win_msg); pCMsgHdr != NULL; pCMsgHdr = WSA_CMSG_NXTHDR(&win_msg, pCMsgHdr)) {
			if ((pCMsgHdr->cmsg_level == IPPROTO_IPV6) && (pCMsgHdr->cmsg_type == IPV6_PKTINFO)) {
				memcpy((void *)&dst.sin6_addr, (const void *) dstaddr(pCMsgHdr), sizeof(struct in6_addr));
			}
		}
#endif
		ip6_m = sctp_get_mbuf_for_msg(sizeof(struct ip6_hdr), 1, M_DONTWAIT, 1, MT_DATA);
		ip6 = mtod(ip6_m, struct ip6_hdr *);
		bzero((void *)ip6, sizeof(struct ip6_hdr));
		ip6->ip6_vfc = IPV6_VERSION;
		ip6->ip6_plen = htons(n);
		ip6->ip6_src = src.sin6_addr;
		ip6->ip6_dst = dst.sin6_addr;

		SCTP_HEADER_LEN(ip6_m) = (int)sizeof(struct ip6_hdr) + n;
		SCTP_BUF_LEN(ip6_m) = sizeof(struct ip6_hdr);
		SCTP_BUF_NEXT(ip6_m) = recvmbuf6[0];
		/* process incoming data */
		/* sctp_input frees this mbuf. */
		SCTPDBG(SCTP_DEBUG_INPUT1, "%s: Received %d bytes.", __func__, n);
		SCTPDBG(SCTP_DEBUG_INPUT1, " - calling sctp6_input with off=%d\n", (int)sizeof(struct ip6_hdr));

		offset = sizeof(struct ip6_hdr);
		sctp6_input_with_port(&ip6_m, &offset, 0);
	}
	return NULL;
}
#endif

/* need ref to this for destroy... */
struct mbuf **udprecvmbuf;

static void *
recv_function_udp(void *arg)
{
	/*Initially the entire set of mbufs is to be allocated.
	  to_fill indicates this amount. */
	int to_fill = MAXLEN_MBUF_CHAIN;
	/* iovlen is the size of each mbuf in the chain */
	int i, n, ncounter;
	int iovlen = MCLBYTES;
	int want_ext = (iovlen > MLEN)? 1 : 0;
	int want_header = 0;
	struct ip *ip;
	struct mbuf *ip_m;
	struct sockaddr_in src, dst;
	char cmsgbuf[DSTADDR_DATASIZE];
#if !defined(__Userspace_os_Windows)
	struct iovec iov[MAXLEN_MBUF_CHAIN];
	struct msghdr msg;
	struct cmsghdr *cmsgptr;
#else
	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	LPFN_WSARECVMSG WSARecvMsg;
	char ControlBuffer[1024];
	WSABUF iov[MAXLEN_MBUF_CHAIN];
	WSAMSG win_msg;
	int nResult, m_ErrorCode;
	WSACMSGHDR *pCMsgHdr;
#endif

	udprecvmbuf = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);

	while (1) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			udprecvmbuf[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
#if !defined(__Userspace_os_Windows)
			iov[i].iov_base = (caddr_t)udprecvmbuf[i]->m_data;
			iov[i].iov_len = iovlen;
#else
			iov[i].buf = (caddr_t)udprecvmbuf[i]->m_data;
			iov[i].len = iovlen;
#endif
		}
		to_fill = 0;
#if !defined(__Userspace_os_Windows)
		bzero((void *)&msg, sizeof(struct msghdr));
#else
		bzero((void *)&win_msg, sizeof(WSAMSG));
#endif
		bzero((void *)&src, sizeof(struct sockaddr_in));
		bzero((void *)&dst, sizeof(struct sockaddr_in));
		bzero((void *)cmsgbuf, DSTADDR_DATASIZE);

#if !defined(__Userspace_os_Windows)
		msg.msg_name = (void *)&src;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		msg.msg_iov = iov;
		msg.msg_iovlen = MAXLEN_MBUF_CHAIN;
		msg.msg_control = (void *)cmsgbuf;
		msg.msg_controllen = DSTADDR_DATASIZE;
		msg.msg_flags = 0;

		ncounter = n = recvmsg(userspace_udpsctp, &msg, 0);
		if (n < 0) {
			continue;
		}
#else
		nResult = WSAIoctl(userspace_udpsctp, SIO_GET_EXTENSION_FUNCTION_POINTER,
		 &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
		 &WSARecvMsg, sizeof WSARecvMsg,
		 &ncounter, NULL, NULL);
		if (nResult == SOCKET_ERROR) {
			m_ErrorCode = WSAGetLastError();
			WSARecvMsg = NULL;
		}
		win_msg.name = (void *)&src;
		win_msg.namelen = sizeof(struct sockaddr_in);
		win_msg.lpBuffers = iov;
		win_msg.dwBufferCount = MAXLEN_MBUF_CHAIN;
		win_msg.Control.len = sizeof ControlBuffer;
		win_msg.Control.buf = ControlBuffer;
		win_msg.dwFlags = 0;
		nResult = WSARecvMsg(userspace_udpsctp, &win_msg, &ncounter, NULL, NULL);
		if (nResult != 0) {
			m_ErrorCode = WSAGetLastError();
		}
		n = ncounter;
#endif
		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(udprecvmbuf[0]) = n; /* length of total packet */

		if (n <= iovlen) {
			SCTP_BUF_LEN(udprecvmbuf[0]) = n;
			(to_fill)++;
		} else {
			i = 0;
			SCTP_BUF_LEN(udprecvmbuf[0]) = iovlen;

			ncounter -= iovlen;
			(to_fill)++;
			do {
				udprecvmbuf[i]->m_next = udprecvmbuf[i+1];
				SCTP_BUF_LEN(udprecvmbuf[i]->m_next) = min(ncounter, iovlen);
				i++;
				ncounter -= iovlen;
				(to_fill)++;
			} while (ncounter > 0);
		}
		assert(to_fill <= MAXLEN_MBUF_CHAIN);

#if !defined(__Userspace_os_Windows)
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
			if ((cmsgptr->cmsg_level == IPPROTO_IP) && (cmsgptr->cmsg_type == DSTADDR_SOCKOPT)) {
				dst.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
				dst.sin_len = sizeof(struct sockaddr_in);
#endif
				dst.sin_port = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
				memcpy((void *)&dst.sin_addr, (const void *) dstaddr(cmsgptr), sizeof(struct in_addr));
			}
		}
#else
		for (pCMsgHdr = WSA_CMSG_FIRSTHDR(&win_msg); pCMsgHdr != NULL; pCMsgHdr = WSA_CMSG_NXTHDR(&win_msg, pCMsgHdr)) {
			if ((pCMsgHdr->cmsg_level == IPPROTO_IP) && (pCMsgHdr->cmsg_type == DSTADDR_SOCKOPT)) {
				dst.sin_family = AF_INET;
				dst.sin_port = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
				memcpy((void *)&dst.sin_addr, (const void *) dstaddr(pCMsgHdr), sizeof(struct in_addr));
			}
		}
#endif

		ip_m = sctp_get_mbuf_for_msg(sizeof(struct ip), 1, M_DONTWAIT, 1, MT_DATA);

		ip = mtod(ip_m, struct ip *);
		bzero((void *)ip, sizeof(struct ip));
		ip->ip_v = IPVERSION;
		ip->ip_len = n;
#if defined(__Userspace_os_Linux) ||  defined(__Userspace_os_Windows)
		ip->ip_len += sizeof(struct ip);
#endif
#if defined(__Userspace_os_Windows)
		ip->ip_len = htons(ip->ip_len);
#endif
		ip->ip_src = src.sin_addr;
		ip->ip_dst = dst.sin_addr;
		SCTP_HEADER_LEN(ip_m) = sizeof(struct ip) + n;
		SCTP_BUF_LEN(ip_m) = sizeof(struct ip);
		SCTP_BUF_NEXT(ip_m) = udprecvmbuf[0];

		SCTPDBG(SCTP_DEBUG_INPUT1, "%s: Received %d bytes.", __func__, n);
		SCTPDBG(SCTP_DEBUG_INPUT1, " - calling sctp_input with off=%d\n", (int)sizeof(struct ip));

		/* process incoming data */
		/* sctp_input frees this mbuf. */
		sctp_input_with_port(ip_m, sizeof(struct ip), src.sin_port);
	}
	return NULL;
}

#if defined(INET6)
struct mbuf **udprecvmbuf6;
static void *
recv_function_udp6(void *arg)
{
	/*Initially the entire set of mbufs is to be allocated.
	  to_fill indicates this amount. */
	int to_fill = MAXLEN_MBUF_CHAIN;
	/* iovlen is the size of each mbuf in the chain */
	int i, n, ncounter, offset;
	int iovlen = MCLBYTES;
	int want_ext = (iovlen > MLEN)? 1 : 0;
	int want_header = 0;
	struct ip6_hdr *ip6;
	struct mbuf *ip6_m;
	struct sockaddr_in6 src, dst;
	char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
#if !defined(__Userspace_os_Windows)
	struct iovec iov[MAXLEN_MBUF_CHAIN];
	struct msghdr msg;
	struct cmsghdr *cmsgptr;
#else
	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	LPFN_WSARECVMSG WSARecvMsg;
	char ControlBuffer[1024];
	WSABUF iov[MAXLEN_MBUF_CHAIN];
	WSAMSG win_msg;
	int nResult, m_ErrorCode;
	WSACMSGHDR *pCMsgHdr;
#endif

	udprecvmbuf6 = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);

	for (;;) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			udprecvmbuf6[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
#if !defined(__Userspace_os_Windows)
			iov[i].iov_base = (caddr_t)udprecvmbuf6[i]->m_data;
			iov[i].iov_len = iovlen;
#else
			iov[i].buf = (caddr_t)udprecvmbuf6[i]->m_data;
			iov[i].len = iovlen;
#endif
		}
		to_fill = 0;

#if !defined(__Userspace_os_Windows)
		bzero((void *)&msg, sizeof(struct msghdr));
#else
		bzero((void *)&win_msg, sizeof(WSAMSG));
#endif
		bzero((void *)&src, sizeof(struct sockaddr_in6));
		bzero((void *)&dst, sizeof(struct sockaddr_in6));
		bzero((void *)cmsgbuf, CMSG_SPACE(sizeof (struct in6_pktinfo)));

#if !defined(__Userspace_os_Windows)
		msg.msg_name = (void *)&src;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		msg.msg_iov = iov;
		msg.msg_iovlen = MAXLEN_MBUF_CHAIN;
		msg.msg_control = (void *)cmsgbuf;
		msg.msg_controllen = (socklen_t)CMSG_LEN(sizeof (struct in6_pktinfo));
		msg.msg_flags = 0;

		ncounter = n = recvmsg(userspace_udpsctp6, &msg, 0);
		if (n < 0) {
			continue;
		}
#else
		nResult = WSAIoctl(userspace_udpsctp6, SIO_GET_EXTENSION_FUNCTION_POINTER,
		                   &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
		                   &WSARecvMsg, sizeof WSARecvMsg,
		                   &ncounter, NULL, NULL);
		if (nResult == SOCKET_ERROR) {
			m_ErrorCode = WSAGetLastError();
			WSARecvMsg = NULL;
		}
		win_msg.name = (void *)&src;
		win_msg.namelen = sizeof(struct sockaddr_in6);
		win_msg.lpBuffers = iov;
		win_msg.dwBufferCount = MAXLEN_MBUF_CHAIN;
		win_msg.Control.len = sizeof ControlBuffer;
		win_msg.Control.buf = ControlBuffer;
		win_msg.dwFlags = 0;
		nResult = WSARecvMsg(userspace_udpsctp6, &win_msg, &ncounter, NULL, NULL);
		if (nResult != 0) {
			m_ErrorCode = WSAGetLastError();
		}
		n = ncounter;
#endif
		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(udprecvmbuf6[0]) = n; /* length of total packet */

		if (n <= iovlen) {
			SCTP_BUF_LEN(udprecvmbuf6[0]) = n;
			(to_fill)++;
		} else {
			i = 0;
			SCTP_BUF_LEN(udprecvmbuf6[0]) = iovlen;

			ncounter -= iovlen;
			(to_fill)++;
			do {
				udprecvmbuf6[i]->m_next = udprecvmbuf6[i+1];
				SCTP_BUF_LEN(udprecvmbuf6[i]->m_next) = min(ncounter, iovlen);
				i++;
				ncounter -= iovlen;
				(to_fill)++;
			} while (ncounter > 0);
		}
		assert(to_fill <= MAXLEN_MBUF_CHAIN);

#if !defined(__Userspace_os_Windows)
		for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
			if ((cmsgptr->cmsg_level == IPPROTO_IPV6) && (cmsgptr->cmsg_type == IPV6_PKTINFO)) {
				dst.sin6_family = AF_INET6;
#if !defined(__Userspace_os_Linux)
				dst.sin6_len = sizeof(struct sockaddr_in6);
#endif
				dst.sin6_port = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
				memcpy((void *)&dst.sin6_addr, (const void *) (&((struct in6_pktinfo *)CMSG_DATA(cmsgptr))->ipi6_addr), sizeof(struct in6_addr));
			}
		}
#else
    for (pCMsgHdr = WSA_CMSG_FIRSTHDR(&win_msg); pCMsgHdr != NULL; pCMsgHdr = WSA_CMSG_NXTHDR(&win_msg, pCMsgHdr)) {
			if ((pCMsgHdr->cmsg_level == IPPROTO_IPV6) && (pCMsgHdr->cmsg_type == IPV6_PKTINFO)) {
				dst.sin6_family = AF_INET6;
				dst.sin6_port = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
				memcpy((void *)&dst.sin6_addr, (const void *) dstaddr(pCMsgHdr), sizeof(struct in6_addr));
			}
		}
#endif

		ip6_m = sctp_get_mbuf_for_msg(sizeof(struct ip6_hdr), 1, M_DONTWAIT, 1, MT_DATA);

		ip6 = mtod(ip6_m, struct ip6_hdr *);
		bzero((void *)ip6, sizeof(struct ip6_hdr));
		ip6->ip6_vfc = IPV6_VERSION;
		ip6->ip6_plen = htons(n);
		ip6->ip6_src = src.sin6_addr;
		ip6->ip6_dst = dst.sin6_addr;
		SCTP_HEADER_LEN(ip6_m) = (int)sizeof(struct ip6_hdr) + n;
		SCTP_BUF_LEN(ip6_m) = sizeof(struct ip6_hdr);
		SCTP_BUF_NEXT(ip6_m) = udprecvmbuf6[0];

		SCTPDBG(SCTP_DEBUG_INPUT1, "%s: Received %d bytes.", __func__, n);
		SCTPDBG(SCTP_DEBUG_INPUT1, " - calling sctp_input with off=%d\n", (int)sizeof(struct ip));

		/* process incoming data */
		/* sctp_input frees this mbuf. */
		offset = sizeof(struct ip6_hdr);
		sctp6_input_with_port(&ip6_m, &offset, src.sin6_port);
	}
	return NULL;
}
#endif

static int
setReceiveBufferSize(int sfd, int new_size)
{
	int ch = new_size;
	if (setsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)&ch, sizeof(ch)) < 0) {
		perror("setReceiveBufferSize setsockopt: SO_RCVBUF failed !\n");
		exit(1);
	}
	return 0;
}

static int
setSendBufferSize(int sfd, int new_size)
{
	int ch = new_size;
	if (setsockopt (sfd, SOL_SOCKET, SO_SNDBUF, (void*)&ch, sizeof(ch)) < 0) {
		perror("setSendBufferSize setsockopt: SO_RCVBUF failed !\n");
		exit(1);
	}
	return 0;
}

void 
recv_thread_init(void)
{
	userland_thread_t recvthreadraw , recvthreadudp;
	const int hdrincl = 1;
	const int on = 1;
	struct sockaddr_in addr_ipv4;
#if defined(INET6)
	userland_thread_t recvthreadraw6, recvthreadudp6;
	struct sockaddr_in6 addr_ipv6;
#endif

#if !defined(__Userspace_os_Windows)
	userland_thread_t recvthreadroute;

	if (userspace_route == -1) {
		if ((userspace_route = socket(AF_ROUTE, SOCK_RAW, 0)) < 0) {
			perror("routing socket failure\n");
		}
	}
#endif
	/* use raw socket, create if not initialized */
	if (userspace_rawsctp == -1) {
		if ((userspace_rawsctp = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP)) < 0) {
			perror("raw socket failure. continue with only UDP socket...\n");
		} else {
			/* complete setting up the raw SCTP socket */
			if (setsockopt(userspace_rawsctp, IPPROTO_IP, IP_HDRINCL,(const void*)&hdrincl, sizeof(int)) < 0) {
				perror("raw setsockopt failure\n");
				exit(1);
			}

			memset((void *)&addr_ipv4, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
			addr_ipv4.sin_len         = sizeof(struct sockaddr_in);
#endif
			addr_ipv4.sin_family      = AF_INET;
			addr_ipv4.sin_port        = htons(0);
			addr_ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
			if (bind(userspace_rawsctp, (const struct sockaddr *)&addr_ipv4, sizeof(struct sockaddr_in)) < 0) {
				perror("bind");
				exit(1);
			}

			setReceiveBufferSize(userspace_rawsctp, SB_RAW); /* 128K */
			setSendBufferSize(userspace_rawsctp, SB_RAW); /* 128K Is this setting net.inet.raw.maxdgram value? Should it be set to 64K? */
		}
	}

	 /* use UDP socket, create if not initialized */
	if (userspace_udpsctp == -1) {
		if ((userspace_udpsctp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			perror("UDP socket failure");
		}
		if (setsockopt(userspace_udpsctp, IPPROTO_IP, DSTADDR_SOCKOPT, (const void *)&on, (int)sizeof(int)) < 0) {
			perror("setsockopt: DSTADDR_SOCKOPT");
			exit(1);
		}
		memset((void *)&addr_ipv4, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
		addr_ipv4.sin_len         = sizeof(struct sockaddr_in);
#endif
		addr_ipv4.sin_family      = AF_INET;
		addr_ipv4.sin_port        = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
		addr_ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(userspace_udpsctp, (const struct sockaddr *)&addr_ipv4, sizeof(struct sockaddr_in)) < 0) {
			perror("bind");
			close(userspace_udpsctp);
			userspace_udpsctp = -1;
		} else {
			setReceiveBufferSize(userspace_udpsctp, SB_RAW); /* 128K */
			setSendBufferSize(userspace_udpsctp, SB_RAW); /* 128K Is this setting net.inet.raw.maxdgram value? Should it be set to 64K? */
		}
	}
#if defined(INET6)
	if (userspace_rawsctp6 == -1) {
		if ((userspace_rawsctp6 = socket(AF_INET6, SOCK_RAW, IPPROTO_SCTP)) < 0) {
			perror("raw ipv6 socket failure. continue with only UDP6 socket...\n");
		} else {
			/* complete setting up the raw SCTP socket */
#if defined(IPV6_RECVPKTINFO)
			if (setsockopt(userspace_rawsctp6, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void *)&on, (int)sizeof(int)) < 0) {
				perror("raw6 setsockopt: IPV6_RECVPKTINFO");
				exit(1);
			}
#else
			if (setsockopt(userspace_rawsctp6, IPPROTO_IPV6, IPV6_PKTINFO,(const void*)&on, sizeof(on)) < 0) {
				perror("raw6 setsockopt: IPV6_PKTINFO\n");
				exit(1);
			}
#endif
			if (setsockopt(userspace_rawsctp6, IPPROTO_IPV6, IPV6_V6ONLY, (const void*)&on, (socklen_t)sizeof(on)) < 0) {
				perror("ipv6only");
			}

			memset((void *)&addr_ipv6, 0, sizeof(struct sockaddr_in6));
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
			addr_ipv6.sin6_len         = sizeof(struct sockaddr_in6);
#endif
			addr_ipv6.sin6_family      = AF_INET6;
			addr_ipv6.sin6_port        = htons(0);
			addr_ipv6.sin6_addr        = in6addr_any;
			if (bind(userspace_rawsctp6, (const struct sockaddr *)&addr_ipv6, sizeof(struct sockaddr_in6)) < 0) {
				perror("bind");
				exit(1);
			}

			setReceiveBufferSize(userspace_rawsctp6, SB_RAW); /* 128K */
			setSendBufferSize(userspace_rawsctp6, SB_RAW); /* 128K Is this setting net.inet.raw.maxdgram value? Should it be set to 64K? */
		}
	}

	if (userspace_udpsctp6 == -1) {
		if ((userspace_udpsctp6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			perror("UDP ipv6 socket failure");
		}
#if defined(IPV6_RECVPKTINFO)
		if (setsockopt(userspace_udpsctp6, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void *)&on, (int)sizeof(int)) < 0) {
			perror("udp6 setsockopt: IPV6_RECVPKTINFO");
			exit(1);
		}
#else
		if (setsockopt(userspace_udpsctp6, IPPROTO_IPV6, IPV6_PKTINFO, (const void *)&on, (int)sizeof(int)) < 0) {
			perror("udp6 setsockopt: IPV6_PKTINFO");
			exit(1);
		}
#endif
		if (setsockopt(userspace_udpsctp6, IPPROTO_IPV6, IPV6_V6ONLY, (const void*)&on, (socklen_t)sizeof(on)) < 0) {
			  perror("ipv6only");
		}
		memset((void *)&addr_ipv6, 0, sizeof(struct sockaddr_in6));
#if !defined(__Userspace_os_Linux) && !defined(__Userspace_os_Windows)
		addr_ipv6.sin6_len         = sizeof(struct sockaddr_in6);
#endif
		addr_ipv6.sin6_family      = AF_INET6;
		addr_ipv6.sin6_port        = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
		addr_ipv6.sin6_addr        = in6addr_any;
		if (bind(userspace_udpsctp6, (const struct sockaddr *)&addr_ipv6, sizeof(struct sockaddr_in6)) < 0) {
			perror("bind");
			close(userspace_udpsctp6);
			userspace_udpsctp6 = -1;
		} else {
			setReceiveBufferSize(userspace_udpsctp6, SB_RAW); /* 128K */
			setSendBufferSize(userspace_udpsctp6, SB_RAW); /* 128K Is this setting net.inet.raw.maxdgram value? Should it be set to 64K? */
		}
	}
#endif

	/* start threads here for receiving incoming messages */
#if !defined(__Userspace_os_Windows)
	if (userspace_route != -1) {
		int rc;

		if ((rc = pthread_create(&recvthreadroute, NULL, &recv_function_route, NULL))) {
			printf("ERROR; return code from recvthread route pthread_create() is %d\n", rc);
			exit(1);
		}
	}
#if defined(INET)
	if (userspace_rawsctp != -1) {
		int rc;

		if ((rc = pthread_create(&recvthreadraw, NULL, &recv_function_raw, NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
	if (userspace_udpsctp != -1) {
		int rc;

		if ((rc = pthread_create(&recvthreadudp, NULL, &recv_function_udp, NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
#endif
#if defined(INET6)
	if (userspace_rawsctp6 != -1) {
		int rc;

		if ((rc = pthread_create(&recvthreadraw6, NULL, &recv_function_raw6, NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
	if (userspace_udpsctp6 != -1) {
		int rc;

		if ((rc = pthread_create(&recvthreadudp6, NULL, &recv_function_udp6, NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
#endif
#else
#if defined(INET)
	if (userspace_rawsctp != -1) {
		if ((recvthreadraw = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&recv_function_raw, NULL, 0, NULL))==NULL) {
			printf("ERROR; Creating recvthreadraw failed\n");
			exit(1);
		}
	}
	if (userspace_udpsctp != -1) {
		if ((recvthreadudp = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&recv_function_udp, NULL, 0, NULL))==NULL) {
			printf("ERROR; Creating recvthreadudp failed\n");
			exit(1);
		}
	}
#endif
#if defined(INET6)
	if (userspace_rawsctp6 != -1) {
		if ((recvthreadraw6 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&recv_function_raw6, NULL, 0, NULL))==NULL) {
			printf("ERROR; Creating recvthreadraw6 failed\n");
			exit(1);
		}
	}
	if (userspace_udpsctp6 != -1) {
		if ((recvthreadudp6 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&recv_function_udp6, NULL, 0, NULL))==NULL) {
			printf("ERROR; Creating recvthreadudp6 failed\n");
			exit(1);
		}
	}
#endif
#endif
}

void
recv_thread_destroy(void)
{
	int i;

	if (userspace_route != -1) {
#if defined(__Userspace_os_Windows)
		closesocket(userspace_route);
#else
		close(userspace_route);
#endif
	}
	if (userspace_rawsctp != -1) {
#if defined(__Userspace_os_Windows)
		closesocket(userspace_rawsctp);
#else
		close(userspace_rawsctp);
#endif
		for(i=0; i < MAXLEN_MBUF_CHAIN; i++) {
			m_free(recvmbuf[i]);
		}
		/* free the array itself */
		free(recvmbuf);
	}
	if (userspace_udpsctp != -1) {
#if defined(__Userspace_os_Windows)
		closesocket(userspace_udpsctp);
#else
		close(userspace_udpsctp);
#endif
		for (i = 0; i < MAXLEN_MBUF_CHAIN; i++) {
			m_free(udprecvmbuf[i]);
		}
		/* free the array itself */
		free(udprecvmbuf);
	}
#if defined(INET6)
	if (userspace_rawsctp6 != -1) {
#if defined(__Userspace_os_Windows)
		closesocket(userspace_rawsctp6);
#else
		close(userspace_rawsctp6);
#endif
		for (i = 0; i < MAXLEN_MBUF_CHAIN; i++) {
			m_free(recvmbuf6[i]);
		}
		/* free the array itself */
		free(recvmbuf6);
	}
	if (userspace_udpsctp6 != -1) {
#if defined(__Userspace_os_Windows)
		closesocket(userspace_udpsctp6);
#else
		close(userspace_udpsctp6);
#endif
		for (i = 0; i < MAXLEN_MBUF_CHAIN; i++) {
			m_free(udprecvmbuf6[i]);
		}
		/* free the array itself */
		free(udprecvmbuf6);
	}
#endif
}
