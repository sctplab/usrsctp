/* __Userspace__ version of sctp_callout.c file */


#include <netinet/sctp_os.h>
#include "user_sctp_callout.h"
#include <netinet/sctp_pcb.h>

static int onetime_timer_initialization = 0;


void
sctp_os_timer_init(sctp_os_timer_t *c)
{
	bzero(c, sizeof(*c));
}

void
sctp_os_timer_start(sctp_os_timer_t *c, int to_ticks, void (*ftn) (void *),
		    void *arg)
{
    /* if timer_init() not called previously, then call it */
    if (!onetime_timer_initialization)
        {
            onetime_timer_initialization = 1;
            timer_init();            
        }
    
    /* paranoia */
    if ((c == NULL) || (ftn == NULL))
        return;
    
    SCTP_TIMERQ_LOCK();
    /* check to see if we're rescheduling a timer */
    if (c->c_flags & SCTP_CALLOUT_PENDING) {
        TAILQ_REMOVE(&SCTP_BASE_INFO(callqueue), c, tqe);
        /*
         * part of the normal "stop a pending callout" process
         * is to clear the CALLOUT_ACTIVE and CALLOUT_PENDING
         * flags.  We don't bother since we are setting these
         * below and we still hold the lock.
         */
    }
    
    /*
     * We could unlock here and lock at the TAILQ_INSERT_TAIL,
     * but there's no point since doing this setup doesn't take much time.
     */
    if (to_ticks <= 0)
        to_ticks = 1;
    
    c->c_arg = arg;
    c->c_flags = (SCTP_CALLOUT_ACTIVE | SCTP_CALLOUT_PENDING);
    c->c_func = ftn;
    c->c_time = uticks + to_ticks;
    TAILQ_INSERT_TAIL(&SCTP_BASE_INFO(callqueue), c, tqe);
    SCTP_TIMERQ_UNLOCK();
    
}

int
sctp_os_timer_stop(sctp_os_timer_t *c)
{

	SCTP_TIMERQ_LOCK();
	/*
	 * Don't attempt to delete a callout that's not on the queue.
	 */
	if (!(c->c_flags & SCTP_CALLOUT_PENDING)) {
		c->c_flags &= ~SCTP_CALLOUT_ACTIVE;
		SCTP_TIMERQ_UNLOCK();
		return (0);
	}
	c->c_flags &= ~(SCTP_CALLOUT_ACTIVE | SCTP_CALLOUT_PENDING);

	TAILQ_REMOVE(&SCTP_BASE_INFO(callqueue), c, tqe);
	SCTP_TIMERQ_UNLOCK();
	return (1);
}
