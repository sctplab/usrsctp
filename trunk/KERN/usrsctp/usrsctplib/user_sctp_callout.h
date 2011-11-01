/* __Userspace__ version of sctp_callout.h file */
#include <sys/queue.h> 
#include <stdlib.h>
#include <sys/types.h>


#ifndef __USER_SCTP_CALLOUT__
#define __USER_SCTP_CALLOUT__


/*
 * __Userspace__  
 * NOTE: the following MACROS are required for locking the callout
 * queue along with a lock/mutex in the OS specific headers and
 * implementation files::
 * - SCTP_TIMERQ_LOCK()
 * - SCTP_TIMERQ_UNLOCK()
 * - SCTP_TIMERQ_LOCK_INIT()
 * - SCTP_TIMERQ_LOCK_DESTROY()
 *
 * SCTP_TIMERQ_LOCK protects:
 * - sctppcbinfo.callqueue
 */


#define SCTP_TIMERQ_LOCK()          (void)pthread_mutex_lock(&timer_mtx)
#define SCTP_TIMERQ_UNLOCK()        (void)pthread_mutex_unlock(&timer_mtx)
#define SCTP_TIMERQ_LOCK_INIT()     (void)pthread_mutex_init(&timer_mtx, NULL)
#define SCTP_TIMERQ_LOCK_DESTROY()  (void)pthread_mutex_destroy(&timer_mtx)

#define _USER_SCTP_NEEDS_CALLOUT_ 1

extern int uticks;
extern void timer_init();
extern pthread_mutex_t timer_mtx;

TAILQ_HEAD(calloutlist, sctp_callout);

struct sctp_callout {
	TAILQ_ENTRY(sctp_callout) tqe;
	int c_time;		/* ticks to the event */
	void *c_arg;		/* function argument */
	void (*c_func)(void *);	/* function to call */
	int c_flags;		/* state of this entry */
};
typedef struct sctp_callout sctp_os_timer_t;

#define	SCTP_CALLOUT_ACTIVE	0x0002	/* callout is currently active */
#define	SCTP_CALLOUT_PENDING	0x0004	/* callout is waiting for timeout */

void sctp_os_timer_init(sctp_os_timer_t *tmr);
void sctp_os_timer_start(sctp_os_timer_t *, int, void (*)(void *), void *);
int sctp_os_timer_stop(sctp_os_timer_t *);

#define SCTP_OS_TIMER_INIT	sctp_os_timer_init
#define SCTP_OS_TIMER_START	sctp_os_timer_start
#define SCTP_OS_TIMER_STOP	sctp_os_timer_stop
/* MT FIXME: Is the following correct? */
#define SCTP_OS_TIMER_STOP_DRAIN SCTP_OS_TIMER_STOP
#define	SCTP_OS_TIMER_PENDING(tmr) ((tmr)->c_flags & SCTP_CALLOUT_PENDING)
#define	SCTP_OS_TIMER_ACTIVE(tmr) ((tmr)->c_flags & SCTP_CALLOUT_ACTIVE)
#define	SCTP_OS_TIMER_DEACTIVATE(tmr) ((tmr)->c_flags &= ~SCTP_CALLOUT_ACTIVE)


#endif
