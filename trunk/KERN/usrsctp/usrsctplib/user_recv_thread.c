#include <sys/types.h>
#include <sys/socket.h>
#if 0
#include <sys/uio.h>
#endif
#include <unistd.h>
#include <pthread.h>
#include <netinet/sctp_os.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>


/* extern __Userspace__ variable in user_recv_thread.h */
int userspace_rawsctp = -1; /* needs to be declared = -1 */
int userspace_udpsctp = -1; 
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

void recv_thread_destroy_udp(void *);
void recv_thread_destroy_raw(void *);
const int MAXLEN_MBUF_CHAIN = 32; /* What should this value be? */

/* need ref to this for destroy... */
struct mbuf **recvmbuf;

static void *
recv_function_raw(void *arg)
{
	struct iovec recv_iovec[MAXLEN_MBUF_CHAIN];
	int iovcnt = MAXLEN_MBUF_CHAIN;
	/*Initially the entire set of mbufs is to be allocated.
	  to_fill indicates this amount. */
	int to_fill = MAXLEN_MBUF_CHAIN;
	/* iovlen is the size of each mbuf in the chain */
	int i, n, ncounter;
	int iovlen = MCLBYTES;
	int want_ext = (iovlen > MLEN)? 1 : 0;
	int want_header = 0;

        recvmbuf = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);
        /* why can't I compile with this? */
#if 0
        pthread_cleanup_push(recv_thread_destroy_raw, NULL);
#endif
        
	while (1) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			recvmbuf[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
			recv_iovec[i].iov_base = (caddr_t)recvmbuf[i]->m_data;
			recv_iovec[i].iov_len = iovlen;
		}
		to_fill = 0;
		
		ncounter = n = readv(userspace_rawsctp, recv_iovec, iovcnt);
		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(recvmbuf[0]) = n; /* length of total packet */
		
		if (n <= iovlen) {
			SCTP_BUF_LEN(recvmbuf[0]) = n;
			(to_fill)++;
		} else {
/* 			printf("%s: n=%d > iovlen=%d\n", __func__, n, iovlen); */
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


/* need ref to this for destroy... */
struct mbuf **udprecvmbuf;

static void *
recv_function_udp(void *arg)
{
	struct iovec iov[MAXLEN_MBUF_CHAIN];
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
	struct msghdr msg;
	struct sockaddr_in src, dst;
	char cmsgbuf[DSTADDR_DATASIZE];
	struct cmsghdr *cmsgptr;

        udprecvmbuf = malloc(sizeof(struct mbuf *) * MAXLEN_MBUF_CHAIN);
        /* why can't I compile with this? */
#if 0
        pthread_cleanup_push(recv_thread_destroy_udp, NULL);
#endif
        
	while (1) {
		for (i = 0; i < to_fill; i++) {
			/* Not getting the packet header. Tests with chain of one run
			   as usual without having the packet header.
			   Have tried both sending and receiving
			 */
			udprecvmbuf[i] = sctp_get_mbuf_for_msg(iovlen, want_header, M_DONTWAIT, want_ext, MT_DATA);
			iov[i].iov_base = (caddr_t)udprecvmbuf[i]->m_data;
			iov[i].iov_len = iovlen;
		}
		to_fill = 0;
		bzero((void *)&msg, sizeof(struct msghdr));
		bzero((void *)&src, sizeof(struct sockaddr_in));
		bzero((void *)&dst, sizeof(struct sockaddr_in));
		bzero((void *)cmsgbuf, DSTADDR_DATASIZE);
		
		msg.msg_name = (void *)&src;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		msg.msg_iov = iov;
		msg.msg_iovlen = MAXLEN_MBUF_CHAIN;
		msg.msg_control = (void *)cmsgbuf;
		msg.msg_controllen = DSTADDR_DATASIZE;
		msg.msg_flags = 0;

		ncounter = n = recvmsg(userspace_udpsctp, &msg, 0);

		assert (n <= (MAXLEN_MBUF_CHAIN * iovlen));
		SCTP_HEADER_LEN(udprecvmbuf[0]) = n; /* length of total packet */
		
		if (n <= iovlen) {
			SCTP_BUF_LEN(udprecvmbuf[0]) = n;
			(to_fill)++;
		} else {
			printf("%s: n=%d > iovlen=%d\n", __func__, n, iovlen);
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

		ip_m = sctp_get_mbuf_for_msg(sizeof(struct ip), 1, M_DONTWAIT, 1, MT_DATA);

		ip = mtod(ip_m, struct ip *);
		bzero((void *)ip, sizeof(struct ip));
		ip->ip_v = IPVERSION;
		ip->ip_p = IPPROTO_UDP; /* tells me over UDP */
		ip->ip_len = n;
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

#if 0
static int
getReceiveBufferSize(int sfd)
{
  int actualbufsize;
  socklen_t intlen = sizeof(int);
  
		if (getsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &actualbufsize, (socklen_t *)&intlen) < 0) {
			perror("setsockopt: rcvbuf");
			exit(1);
		} else {
			fprintf(stdout,"Receive buffer size: %d.\n", actualbufsize);
		}
	return 0;
}

static int
getSendBufferSize(int sfd)
{
  int actualbufsize;
  socklen_t intlen = sizeof(int);
  
		if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &actualbufsize, (socklen_t *)&intlen) < 0) {
			perror("setsockopt: sendbuf");
			exit(1);
		} else {
			fprintf(stdout,"Send buffer size: %d.\n", actualbufsize);
		}
	return 0;
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
	/*printf("setReceiveBufferSize set receive buffer size to : %d bytes\n",ch);*/
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
	/*printf("setSendBufferSize set send buffer size to : %d bytes\n",ch);*/
	return 0;
}

void 
recv_thread_init()
{
	pthread_t recvthreadraw , recvthreadudp;
	int rc;
	const int hdrincl = 1;
	const int on = 1;
	struct sockaddr_in addr_ipv4;

	/* use raw socket, create if not initialized */
	if (userspace_rawsctp == -1) {
            if ((userspace_rawsctp = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP)) < 0) {
                perror("raw socket failure. continue with only UDP socket...\n");
            } else {
                /* complete setting up the raw SCTP socket */
                if (setsockopt(userspace_rawsctp, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(int)) < 0) {
                    perror("raw setsockopt failure\n");
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
			exit(1);
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
			exit(1);
		}
		if (userspace_rawsctp == -1) {
			SCTP_BASE_SYSCTL(sctp_udp_tunneling_for_client_enable) = 1;
		}
		setReceiveBufferSize(userspace_udpsctp, SB_RAW); /* 128K */
		setSendBufferSize(userspace_udpsctp, SB_RAW); /* 128K Is this setting net.inet.raw.maxdgram value? Should it be set to 64K? */
	}

	/* start threads here for receiving incoming messages */
	if (userspace_rawsctp != -1) {
		if ((rc = pthread_create(&recvthreadraw, NULL, &recv_function_raw, (void *)NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
	if (userspace_udpsctp != -1) {
		if ((rc = pthread_create(&recvthreadudp, NULL, &recv_function_udp, (void *)NULL))) {
			printf("ERROR; return code from recvthread pthread_create() is %d\n", rc);
			exit(1);
		}
	}
}


void
recv_thread_destroy_raw(void *parm) {

    int i;

    /* close sockets if they are open */
    if (userspace_route != -1)
        close(userspace_route);
    if (userspace_rawsctp != -1)
        close(userspace_rawsctp);

    /* 
     *  call m_free on contents of recvmbuf array
     */
    for(i=0; i < MAXLEN_MBUF_CHAIN; i++) {
        m_free(recvmbuf[i]);
    }

    /* free the array itself */
    free(recvmbuf);
    
    
}

void
recv_thread_destroy_udp(void *parm) {

    int i;
    
    /* socket closed in 
    void sctp_over_udp_stop(void)
    */
    
    /* 
     *   call m_free on contents of udprecvmbuf array
     */
    for(i=0; i < MAXLEN_MBUF_CHAIN; i++) {
        m_free(udprecvmbuf[i]);
    }

    /* free the array itself */
    free(udprecvmbuf);

}
