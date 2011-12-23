/* __Userspace__ version of ip6_var.h */

#ifndef _USER_IP6_VAR_H_
#define _USER_IP6_VAR_H_

#if !defined(__Userspace_os_Linux)
#define s6_addr8  __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32

/*
#define IPV6_V6ONLY  27
 */
#else
/*
 #define IPPROTO_DONE 257
 */
struct in6_pktinfo {
	struct in6_addr ipi6_addr;
	int ipi6_ifindex;
};
#endif

struct ip6_moptions {
	struct	ifnet *im6o_multicast_ifp; /* ifp for outgoing multicasts */
	u_char	im6o_multicast_hlim;	/* hoplimit for outgoing multicasts */
	u_char	im6o_multicast_loop;	/* 1 >= hear sends if a member */
	u_short	im6o_num_memberships;	/* no. memberships this socket */
	u_short	im6o_max_memberships;	/* max memberships this socket */
	struct	in6_multi **im6o_membership;	/* group memberships */
	struct	in6_mfilter *im6o_mfilters;	/* source filters */
};

struct route_in6 {
	struct	rtentry *ro_rt;
	struct	llentry *ro_lle;
	struct	in6_addr *ro_ia6;
	int		ro_flags;
	struct	sockaddr_in6 ro_dst;
};

#define IP6_EXTHDR_GET(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	int tmp;							\
	if ((m)->m_len >= (off) + (len))				\
		(val) = (typ)(mtod((m), caddr_t) + (off));		\
	else {								\
		t = m_pulldown((m), (off), (len), &tmp);		\
		if (t) {						\
			if (t->m_len < tmp + (len))			\
				panic("m_pulldown malfunction");	\
			(val) = (typ)(mtod(t, caddr_t) + tmp);		\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while (0)

#endif /* !_USER_IP6_VAR_H_ */
