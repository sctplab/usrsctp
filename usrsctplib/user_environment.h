#ifndef _USER_ENVIRONMENT_H_
#define _USER_ENVIRONMENT_H_
/* __Userspace__ */
#include <sys/types.h>

#ifdef __Userspace_os_FreeBSD
#ifndef _SYS_MUTEX_H_
#include <sys/mutex.h>
#endif
#endif

/* maxsockets is used in SCTP_ZONE_INIT call. It refers to
 * kern.ipc.maxsockets kernel environment variable.
 */ 
extern int maxsockets;

/* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
 * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
 * hz is initialized in void init_param1(void) in that file. 
 */
extern int hz;


/* The following two ints define a range of available ephermal ports. */
extern int ipport_firstauto, ipport_lastauto;

/* nmbclusters is used in sctp_usrreq.c (e.g., sctp_init). In the FreeBSD kernel,
 *  this is 1024 + maxusers * 64.
 */
extern int nmbclusters;


/* __Userspace__ Are min, max defined in some header file? */
#define min(a,b) ((a)>(b)?(b):(a))
#define max(a,b) ((a)>(b)?(a):(b))


extern int read_random(void *buf, int count);

/* errno's may differ per OS.  errno.h now included in sctp_os_userspace.h */
/* Source: /usr/src/sys/sys/errno.h */
/* #define	ENOSPC		28 */		/* No space left on device */
/* #define	ENOBUFS		55 */		/* No buffer space available */
/* #define	ENOMEM		12 */		/* Cannot allocate memory */
/* #define	EACCES		13 */		/* Permission denied */
/* #define	EFAULT		14 */		/* Bad address */
/* #define	EHOSTDOWN	64 */		/* Host is down */
/* #define	EHOSTUNREACH	65 */		/* No route to host */

/* Source ip_output.c. extern'd in ip_var.h */
extern u_short ip_id;

#if defined(__Userspace_os_Linux)
#define IPV6_VERSION            0x60
#endif


/* kernel stuff */
#include <assert.h>
#define KASSERT(exp,msg) assert(exp)

#define panic(arg1)	do { 					\
                            perror(arg1);                       \
                            exit(1);                            \
} while (0)
/* necessary for sctp_pcb.c */
extern int ip_defttl;


/* dummy definitions used (temporarily?) for inpcb userspace port */
#define mtx_lock(arg1)
#define mtx_unlock(arg1)
#define mtx_assert(arg1,arg2)
#define MA_OWNED 7 /* sys/mutex.h typically on FreeBSD */
#if !defined(__Userspace_os_FreeBSD)
struct mtx {};
struct selinfo {};
struct sx {};
#endif

/* called in sctp_usrreq.c */
#define in6_sin_2_v4mapsin6(arg1, arg2) /* STUB */

#endif
