/* __Userspace__ */

#include <stdlib.h>
#if !defined (__Userspace_os_Windows)
#include <stdint.h>
#include <sys/sysctl.h>
#include <netinet/sctp_os_userspace.h>
#endif
#include <user_environment.h>
#include <sys/types.h>
/* #include <sys/param.h> defines MIN */
#if !defined(MIN)
#define MIN(arg1,arg2) ((arg1) < (arg2) ? (arg1) : (arg2))
#endif
#include <string.h>

#define uHZ 1000

/* See user_include/user_environment.h for comments about these variables */
int maxsockets = 25600;
int hz = uHZ;
int ip_defttl = 64;
int ipport_firstauto = 49152, ipport_lastauto = 65535;
int nmbclusters = 65536;

/* Source ip_output.c. extern'd in ip_var.h */
u_short ip_id = 0; /*__Userspace__ TODO Should it be initialized to zero? */

/* used in user_include/user_atomic.h in order to make the operations 
 * defined there truly atomic 
 */
userland_mutex_t atomic_mtx;

/* Source: /usr/src/sys/dev/random/harvest.c */
static int read_random_phony(void *, int);

static int (*read_func)(void *, int) = read_random_phony;

/* Userland-visible version of read_random */
int
read_random(void *buf, int count)
{
	return ((*read_func)(buf, count));
}

/* If the entropy device is not loaded, make a token effort to
 * provide _some_ kind of randomness. This should only be used
 * inside other RNG's, like arc4random(9).
 */
static int
read_random_phony(void *buf, int count)
{
	uint32_t randval;
	int size, i;

	/* srandom() is called in kern/init_main.c:proc0_post() */

	/* Fill buf[] with random(9) output */
	for (i = 0; i < count; i+= (int)sizeof(uint32_t)) {
		randval = random();
		size = MIN(count - i, sizeof(uint32_t));
		memcpy(&((char *)buf)[i], &randval, (size_t)size);
	}

	return (count);
}

