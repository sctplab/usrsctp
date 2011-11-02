#include <sys/types.h> 
#include <sys/wait.h> 
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> 
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_sysctl.h>
#include "netinet/sctp_callout.h"

#define FD_SIZE 1
/* This is the polling time of callqueue in milliseconds
 * 10ms seems to work well. 1ms was giving erratic behavior
 */
#define TIMEOUT_INTERVAL 10 

void *user_sctp_timer_iterate(void * threadname);

void * (*timerFunction)(void *) = {&user_sctp_timer_iterate};

int uticks=0; /* does the value in uticks overflow after some time has elapsed? */
pthread_mutex_t timer_mtx;

#if defined(__Userspace_os_Darwin)
/* This isn't defined on Darwin Kernel Version 8.11.1, so use FreeBSD def */
typedef       long            __suseconds_t;
#endif

void timer_init(){


    pthread_t ithread;
    int rc;
    char* tn={"iterator"};

    /*  No need to do SCTP_TIMERQ_LOCK_INIT(); here, it is being done in sctp_pcb_init() */
    
    /* start one thread here */    
    

    rc = pthread_create(&ithread, NULL, timerFunction, (void *)tn);
    if (rc){
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(1);
        
    }
    
}


void *user_sctp_timer_iterate(void * threadname)
{
    sctp_os_timer_t *c;
    void (*c_func)(void *);
    void *c_arg;
    sctp_os_timer_t *sctp_os_timer_next = NULL;
    /*
     * The MSEC_TO_TICKS conversion depends on hz. The to_ticks in
     * sctp_os_timer_start also depends on hz. E.g. if hz=1000 then
     * for multiple INIT the to_ticks is 2000, 4000, 8000, 16000, 32000, 60000
     *  and further to_ticks level off at 60000 i.e. 60 seconds.
     * If hz=100 then for multiple INIT the to_ticks are 200, 400, 800 and so-on.
     */
    int time_to_ticks = MSEC_TO_TICKS(TIMEOUT_INTERVAL); 
    __suseconds_t timeout_interval = TIMEOUT_INTERVAL  * 1000; /* in microseconds */

    struct timeval timeout;
    struct timeval *timeout_ptr;
    fd_set read_fds;                       
    int fd = 23; /* what should this value be? */
    FD_ZERO(&read_fds);              
    FD_SET(fd, &read_fds);
    
    while(1) {
        
        timeout.tv_sec  = 0; 
        timeout.tv_usec = timeout_interval;
        timeout_ptr = &timeout;
        
        select(FD_SIZE, &read_fds, NULL, NULL, timeout_ptr);    
        

            /* update our tick count */
            uticks += time_to_ticks;
            SCTP_TIMERQ_LOCK();
            c = TAILQ_FIRST(&SCTP_BASE_INFO(callqueue));
            while (c) {
		if (c->c_time <= uticks) {
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


