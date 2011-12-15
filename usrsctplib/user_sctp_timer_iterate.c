#include <sys/types.h> 
#if !defined (__Userspace_os_Windows)
#include <sys/wait.h> 
#include <unistd.h>
#include <pthread.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h> 
#include <errno.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_sysctl.h>
#include "netinet/sctp_callout.h"

/* This is the polling time of callqueue in milliseconds
 * 10ms seems to work well. 1ms was giving erratic behavior
 */
#define TIMEOUT_INTERVAL 10

void *user_sctp_timer_iterate(void * threadname);

void * (*timerFunction)(void *) = {&user_sctp_timer_iterate};

extern int ticks;
userland_mutex_t timer_mtx;

void 
timer_init(void) {
	userland_thread_t ithread;
#if !defined (__Userspace_os_Windows)
	int rc;
#endif
	char *tn = {"iterator"};

	/* No need to do SCTP_TIMERQ_LOCK_INIT(); here, it is being done in sctp_pcb_init() */
	/* start one thread here */
#if defined (__Userspace_os_Windows)
	if ((ithread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)timerFunction, (void *)tn, 0, NULL))==NULL) {
		printf("ERROR; Creating ithread failed\n");
		exit(1);
	}
#else
	rc = pthread_create(&ithread, NULL, timerFunction, (void *)tn);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		exit(1);
	}
#endif
}

void *
user_sctp_timer_iterate(void *threadname)
{
	sctp_os_timer_t *c;
	void (*c_func)(void *);
	void *c_arg;
	sctp_os_timer_t *sctp_os_timer_next;
	/*
	 * The MSEC_TO_TICKS conversion depends on hz. The to_ticks in
	 * sctp_os_timer_start also depends on hz. E.g. if hz=1000 then
	 * for multiple INIT the to_ticks is 2000, 4000, 8000, 16000, 32000, 60000
	 * and further to_ticks level off at 60000 i.e. 60 seconds.
	 * If hz=100 then for multiple INIT the to_ticks are 200, 400, 800 and so-on.
	 */
	struct timeval timeout;

	while(1) {
		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000 * TIMEOUT_INTERVAL;
#if defined (__Userspace_os_Windows)
		Sleep(TIMEOUT_INTERVAL);
#else
		select(0, NULL, NULL, NULL, &timeout);
#endif
		/* update our tick count */
		ticks += MSEC_TO_TICKS(TIMEOUT_INTERVAL);
		SCTP_TIMERQ_LOCK();
		c = TAILQ_FIRST(&SCTP_BASE_INFO(callqueue));
		while (c) {
			if (c->c_time <= ticks) {
				sctp_os_timer_next = TAILQ_NEXT(c, tqe);
				TAILQ_REMOVE(&SCTP_BASE_INFO(callqueue), c, tqe);
				c_func = c->c_func;
				c_arg = c->c_arg;
				c->c_flags &= ~SCTP_CALLOUT_PENDING;
				SCTP_TIMERQ_UNLOCK();
				c_func(c_arg);
				SCTP_TIMERQ_LOCK();
				c = sctp_os_timer_next;
			} else {
				c = TAILQ_NEXT(c, tqe);
			}
		}
		SCTP_TIMERQ_UNLOCK();
	}
	return NULL;
}

