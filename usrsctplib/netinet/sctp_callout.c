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

#if defined(__Userspace__)
#include <sys/types.h>
#if !defined (__Userspace_os_Windows)
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#endif
#if defined(__Userspace_os_NaCl)
#include <sys/select.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <user_atomic.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#else
#include <netinet/sctp_os.h>
#include <netinet/sctp_callout.h>
#include <netinet/sctp_pcb.h>
#endif


#if defined (__Userspace__)
static
void sctp_userland_cond_wait(userland_cond_t* cond, userland_mutex_t* mtx)
{
#if defined (__Userspace_os_Windows)
	SleepConditionVariableCS(cond, mtx, INFINITE);
#else	
	int rc = pthread_cond_wait(cond, mtx);
	if (rc)
		SCTP_PRINTF("ERROR; return code from pthread_cond_wait is %d\n", rc);
#endif
}


static
void sctp_userland_cond_signal(userland_cond_t* cond)
{
#if defined (__Userspace_os_Windows)
	WakeAllConditionVariable(cond);
#else	
	int rc = pthread_cond_broadcast(cond);
	if (rc)
		SCTP_PRINTF("ERROR; return code from pthread_cond_broadcast is %d\n", rc);
#endif
}

static
void sctp_userland_cond_init(userland_cond_t* cond)
{
#if defined (__Userspace_os_Windows)
	InitializeConditionVariable(cond);
#else	
	int rc = pthread_cond_init(cond, NULL);
	if (rc)
		SCTP_PRINTF("ERROR; return code from pthread_cond_init is %d\n", rc);
#endif
}

static
void sctp_userland_cond_destroy(userland_cond_t* cond)
{
#if defined (__Userspace_os_Windows)
	DeleteConditionVariable(cond);
#else	
	int rc = pthread_cond_destroy(cond);
	if (rc)
		SCTP_PRINTF("ERROR; return code from pthread_cond_destroy is %d\n", rc);
#endif
}
#endif


static void
sctp_os_timer_cancel_impl(sctp_os_timer_t* c)
{
	switch (c->c_state)
	{
	case SCTP_CALLOUT_SCHEDULED:
	{
		sctp_binary_heap_remove(&SCTP_BASE_INFO(timers_queue), &c->heap_node);
		c->c_state = SCTP_CALLOUT_COMPLETED;
		break;
	}
	case SCTP_CALLOUT_RUNNING:
	{
		c->c_state = SCTP_CALLOUT_CANCEL_REQUESTED;
		break;
	}
	case SCTP_CALLOUT_CANCEL_REQUESTED:
	case SCTP_CALLOUT_COMPLETED:
	case SCTP_CALLOUT_NEW:
	{
		// nothing to do
		break;
	}
	default:
	{
		KASSERT(0, ("Unknown callout state"));
		break;
	}
	}
}


static void
sctp_os_timer_wait_completion_impl(sctp_os_timer_t* c)
{
	userland_thread_id_t current_tid;
	sctp_userspace_thread_id(&current_tid);

	int retry_condition_wait = 1;
	do
	{
		switch (c->c_state)
		{
		case SCTP_CALLOUT_RUNNING:
		case SCTP_CALLOUT_CANCEL_REQUESTED:
		case SCTP_CALLOUT_SCHEDULED:
		{
			if (current_tid == c->c_executor_id)
			{
				// callout tried to wait for completion of itself
				KASSERT(0, ("Deadlock detected: wait for self completion"));
				retry_condition_wait = 0;
			}
			else
			{
#if defined (__Userspace__)
				sctp_userland_cond_wait(&c->c_completion, &SCTP_BASE_VAR(timer_mtx));
#endif
			}
			break;
		}
		case SCTP_CALLOUT_COMPLETED:
		case SCTP_CALLOUT_NEW:
		{
			retry_condition_wait = 0;
			break;
		}
		default:
		{
			KASSERT(0, ("Unknown callout state"));
			break;
		}
		}
	} while (retry_condition_wait);
}


/*
 * Callout/Timer routines for OS that doesn't have them
 */
#if defined(__APPLE__) || defined(__Userspace__)
static uint32_t ticks = 0;
#else
extern int ticks;
#endif

uint32_t sctp_get_tick_count(void) {
	uint32_t ret;

	SCTP_TIMERQ_LOCK();
	ret = ticks;
	SCTP_TIMERQ_UNLOCK();
	return ret;
}

int
sctp_os_timer_compare(sctp_os_timer_t* a, sctp_os_timer_t* b)
{
	if (SCTP_UINT32_GT(a->c_time, b->c_time))
	{
		return 1;
	}
	if (a->c_time == b->c_time)
	{
		return 0;
	}
	return -1;
}

void
sctp_os_timer_init(sctp_os_timer_t *c)
{
	memset(c, 0, sizeof(*c));
	sctp_binary_heap_node_init(&c->heap_node, c);
#if defined(__Userspace__)
	sctp_userland_cond_init(&c->c_completion);
#endif
}

int sctp_os_timer_is_pending(const sctp_os_timer_t *c)
{
	SCTP_TIMERQ_LOCK();
	const int is_pending = (c->c_state == SCTP_CALLOUT_SCHEDULED);
	SCTP_TIMERQ_UNLOCK();
	return is_pending;
}

int sctp_os_timer_is_active(const sctp_os_timer_t* c)
{
	SCTP_TIMERQ_LOCK();
	const int is_active = !(c->c_state == SCTP_CALLOUT_COMPLETED || c->c_state == SCTP_CALLOUT_NEW);
	SCTP_TIMERQ_UNLOCK();
	return is_active;
}

void
sctp_os_timer_start(sctp_os_timer_t *c, uint32_t to_ticks, void (*ftn) (void *),
                    void *arg)
{
	/* paranoia */
	if ((c == NULL) || (ftn == NULL))
	{
		KASSERT(0, ("Attempted to start NULL timer or NULL callback"));
		return;
	}

	SCTP_TIMERQ_LOCK();

	switch (c->c_state)
	{
	case SCTP_CALLOUT_CANCEL_REQUESTED:
	{
		/* Do not re-schedule cancelled callout which is not yet completed */
		break;
	}
	case SCTP_CALLOUT_SCHEDULED:
	{
		sctp_binary_heap_remove(&SCTP_BASE_INFO(timers_queue), &c->heap_node);
		// Workaround for  -Wimplicit-fallthrough
		goto SCHEDULE_TIMER;
	}
	SCHEDULE_TIMER:
	case SCTP_CALLOUT_RUNNING:
	case SCTP_CALLOUT_NEW:
	case SCTP_CALLOUT_COMPLETED:
	{
		if (to_ticks == 0)
			to_ticks = 1;

		c->c_arg = arg;
		c->c_state = SCTP_CALLOUT_SCHEDULED;
		c->c_func = ftn;
		c->c_time = ticks + to_ticks;

		sctp_binary_heap_push(&SCTP_BASE_INFO(timers_queue), &c->heap_node);
		break;
	}
	default:
		KASSERT(0, ("Unknown callout state"));
	}

	SCTP_TIMERQ_UNLOCK();
}


void
sctp_os_timer_cancel(sctp_os_timer_t* c)
{
	SCTP_TIMERQ_LOCK();
	sctp_os_timer_cancel_impl(c);
	SCTP_TIMERQ_UNLOCK();
}


void
sctp_os_timer_wait_completion(sctp_os_timer_t* c)
{
	SCTP_TIMERQ_LOCK();
	sctp_os_timer_wait_completion_impl(c);
	SCTP_TIMERQ_UNLOCK();
}


int
sctp_os_timer_stop(sctp_os_timer_t *c)
{
	SCTP_TIMERQ_LOCK();
	sctp_os_timer_cancel_impl(c);
	sctp_os_timer_wait_completion_impl(c);
	SCTP_TIMERQ_UNLOCK();
	return (1);
}


void
sctp_handle_tick(uint32_t elapsed_ticks)
{
	SCTP_TIMERQ_LOCK();
	/* update our tick count */
	ticks += elapsed_ticks;

	sctp_binary_heap_t* heap = &SCTP_BASE_INFO(timers_queue);
	sctp_binary_heap_node_t* node = NULL;
	while (0 == sctp_binary_heap_peek(heap, &node))
	{
		sctp_os_timer_t* t = ((sctp_os_timer_t*)node->data);
		if (!SCTP_UINT32_GE(sctp_get_tick_count(), t->c_time))
		{
			// Earliest timer is not ready yet 
			break;
		}
		sctp_binary_heap_remove(heap, node);

		if (t->c_state == SCTP_CALLOUT_SCHEDULED)
		{
			userland_thread_id_t tid;
			sctp_userspace_thread_id(&tid);
			t->c_executor_id = tid;
			t->c_state = SCTP_CALLOUT_RUNNING;

			void (* const c_func)(void*) = t->c_func;
			void* c_arg = t->c_arg;
			SCTP_TIMERQ_UNLOCK();
			c_func(c_arg);
			SCTP_TIMERQ_LOCK();

			t->c_executor_id = 0;
		}

		switch (t->c_state)
		{
		case SCTP_CALLOUT_RUNNING:
		case SCTP_CALLOUT_CANCEL_REQUESTED:
		{
			t->c_state = SCTP_CALLOUT_COMPLETED;
#if defined(__Userspace__)
			sctp_userland_cond_signal(&t->c_completion);
#endif
			break;
		}
		case SCTP_CALLOUT_SCHEDULED:
			// nothing to do, timer is rescheduled
			break;
		case SCTP_CALLOUT_COMPLETED:
		case SCTP_CALLOUT_NEW:
		default:
			KASSERT(0, ("Unexpected timer state"));
			break;
		}

	}

	SCTP_TIMERQ_UNLOCK();
}

#if defined(__APPLE__)
void
sctp_timeout(void *arg SCTP_UNUSED)
{
	sctp_handle_tick(SCTP_BASE_VAR(sctp_main_timer_ticks));
	sctp_start_main_timer();
}
#endif

#if defined(__Userspace__)
#define TIMEOUT_INTERVAL 10

void *
user_sctp_timer_iterate(void *arg)
{
	sctp_userspace_set_threadname("SCTP timer");
	for (;;) {
#if defined (__Userspace_os_Windows)
		Sleep(TIMEOUT_INTERVAL);
#else
		struct timespec amount, remaining;

		remaining.tv_sec = 0;
		remaining.tv_nsec = TIMEOUT_INTERVAL * 1000 * 1000;
		do {
			amount = remaining;
		} while (nanosleep(&amount, &remaining) == -1);
#endif
		if (atomic_cmpset_int(&SCTP_BASE_VAR(timer_thread_should_exit), 1, 1)) {
			break;
		}
		sctp_handle_tick(MSEC_TO_TICKS(TIMEOUT_INTERVAL));
	}
	return (NULL);
}

void
sctp_start_timer(void)
{
	/*
	 * No need to do SCTP_TIMERQ_LOCK_INIT();
	 * here, it is being done in sctp_pcb_init()
	 */
	int rc;
	rc = sctp_userspace_thread_create(&SCTP_BASE_VAR(timer_thread), user_sctp_timer_iterate);
	if (rc) {
		SCTP_PRINTF("ERROR; return code from sctp_thread_create() is %d\n", rc);
	}
}

#endif
