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
#include <inttypes.h>
#include <user_atomic.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#else
#include <netinet/sctp_os.h>
#include <netinet/sctp_callout.h>
#include <netinet/sctp_pcb.h>
#endif

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

/*
 * SCTP_TIMERQ_LOCK protects:
 * - SCTP_BASE_INFO(timers_queue)
 * - sctp_os_timer_current: current callout callback in progress
 * - sctp_os_timer_current_tid: current callout thread id in progress
 * - sctp_os_timer_current_changed: conditional variable signaled when
 *                                  current callout pointer is changed
 */
static sctp_os_timer_t *sctp_os_timer_current = NULL;
static userland_thread_id_t sctp_os_timer_current_tid;
static userland_cond_t sctp_os_timer_current_changed;

#if defined(__Userspace__)

static void
sctp_userland_cond_wait(userland_cond_t* cond,
                        userland_mutex_t* mtx) {
	// callee must be robust to spurious wakeups, both because
	// wakeup could happen due to native API behavior and because
	// there is indendend timeout for wait.
#if defined(__Userspace_os_Windows)
	const DWORD timeoutMillis = 20 * 1000;
	const BOOL waited = SleepConditionVariableCS(cond, mtx, timeoutMillis);
	if (!waited) {
		SCTP_PRINTF("WARN; SleepConditionVariableCS did not return within %ul millis\n", timeoutMillis);
	}
#else
	struct timespec ts;
	ts.tv_sec = 20;
	ts.tv_nsec = 0;
	int rc = pthread_cond_timedwait(cond, mtx, &ts);
	if (rc) {
		if (rc == ETIMEDOUT) {
			SCTP_PRINTF("WARN; pthread_cond_timedwait did not return within %" PRId64 " sec\n",
				(int64_t)ts.tv_sec);
		} else {
			SCTP_PRINTF("ERROR; return code from pthread_cond_wait is %d\n",
				rc);
		}
	}
#endif
}

static void
sctp_userland_cond_signal(userland_cond_t* cond) {
#if defined(__Userspace_os_Windows)
	WakeAllConditionVariable(cond);
#else
	int rc = pthread_cond_broadcast(cond);
	if (rc) {
		SCTP_PRINTF("ERROR; return code from pthread_cond_broadcast is %d\n", rc);
	}
#endif
}

static void
sctp_userland_cond_init(userland_cond_t* cond) {
#if defined(__Userspace_os_Windows)
	InitializeConditionVariable(cond);
#else
	int rc = pthread_cond_init(cond, NULL);
	if (rc) {
		SCTP_PRINTF("ERROR; return code from pthread_cond_init is %d\n", rc);
	}
#endif
}

static void
sctp_userland_cond_destroy(userland_cond_t* cond) {
#if defined(__Userspace_os_Windows)
	DeleteConditionVariable(cond);
#else
	int rc = pthread_cond_destroy(cond);
	if (rc) {
		SCTP_PRINTF("ERROR; return code from pthread_cond_destroy is %d\n", rc);
	}
#endif
}
#endif

static int
sctp_os_timer_cancel_impl(sctp_os_timer_t* c) {
	// Assume SCTP_TIMERQ_LOCK done by caller

	c->c_flags &= ~(SCTP_CALLOUT_ACTIVE);
	c->c_flags |= (SCTP_CALLOUT_CANCELLED);

	if (c->c_flags & SCTP_CALLOUT_PENDING)
	{
		c->c_flags &= ~SCTP_CALLOUT_PENDING;
		sctp_binary_heap_remove(&SCTP_BASE_INFO(timers_queue), &c->heap_node);
		SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": cancelled pending callout %p\n",
			__func__, ticks, c);
		return (1);
	}
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": cancelled non-pending callout %p\n",
		__func__, ticks, c);
	return (0);
}

void
sctp_os_timer_describe(const sctp_os_timer_t* t,
                       size_t max_len,
                       char* buffer) {
	snprintf(buffer, max_len, "t=%" PRIu32 ",a=%p", t->c_time, (void*)t);
}

int
sctp_os_timer_compare(const sctp_os_timer_t* a, const sctp_os_timer_t* b) {
	if (a->c_time == b->c_time) {
		return 0;
	}
	return SCTP_UINT32_GT(a->c_time, b->c_time) ? 1 : -1;
}

void
sctp_os_timer_init(sctp_os_timer_t *c)
{
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": request to init callout %p\n", 
		__func__, sctp_get_tick_count(), c);
	memset(c, 0, sizeof(*c));
	sctp_binary_heap_node_init(&c->heap_node, c);
}

int
sctp_os_timer_is_pending(const sctp_os_timer_t* c) {
	SCTP_TIMERQ_LOCK();
	const int is_pending = (c->c_flags & SCTP_CALLOUT_PENDING);
	SCTP_TIMERQ_UNLOCK();
	return is_pending;
}

int
sctp_os_timer_is_active(const sctp_os_timer_t* c) {
	SCTP_TIMERQ_LOCK();
	const int is_active = (c->c_flags & SCTP_CALLOUT_ACTIVE);
	SCTP_TIMERQ_UNLOCK();
	return is_active;
}

void
sctp_os_timer_deactivate(sctp_os_timer_t* c) {
	SCTP_TIMERQ_LOCK();
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": request to deactivate callout %p\n", 
		__func__, ticks, c);
	c->c_flags &= ~SCTP_CALLOUT_ACTIVE;
	SCTP_TIMERQ_UNLOCK();
}

void
sctp_os_timer_start(sctp_os_timer_t *c, uint32_t to_ticks, void (*ftn) (void *),
                    void *arg)
{
	/* paranoia */
	if ((c == NULL) || (ftn == NULL)) {
		KASSERT(0, ("Timer is NULL or callback is NULL"));
		return;
	}

	SCTP_TIMERQ_LOCK();
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": request to start callout %p with delay of %" PRIu32 " ticks\n", 
		__func__, ticks, c, to_ticks);
	/* check to see if we're rescheduling a timer */
	if (c == sctp_os_timer_current) {
		/*
		 * We're being asked to reschedule a callout which is
		 * currently in progress.
		 */
		if ((c->c_flags & SCTP_CALLOUT_CANCELLED) != 0) {
			/*
			 * This callout is already being stopped.
			 * callout.  Don't reschedule.
			 */
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": callout %p is cancelled\n",
				__func__, ticks, c);
			SCTP_TIMERQ_UNLOCK();
			return;
		}
		if ((c->c_flags & SCTP_CALLOUT_ACTIVE) == 0) {
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": callout %p is executing and deactivated\n",
				__func__, ticks, c);
		}
	}

	const uint32_t target_ticks = ticks + to_ticks;

	sctp_binary_heap_t* timers_queue = &SCTP_BASE_INFO(timers_queue);
	if (c->c_flags & SCTP_CALLOUT_PENDING) {
		sctp_binary_heap_remove(timers_queue, &c->heap_node);
		/*
		 * part of the normal "stop a pending callout" process
		 * is to clear the CALLOUT_ACTIVE and CALLOUT_PENDING
		 * flags.  We don't bother since we are setting these
		 * below and we still hold the lock.
		 */
		SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": rescheduling callout %p from %" PRIu32 " to %" PRIu32 "\n",
			__func__, ticks, c, c->c_time, target_ticks);
	}

	/*
	 * We could unlock/splx here and lock/spl at the TAILQ_INSERT_TAIL,
	 * but there's no point since doing this setup doesn't take much time.
	 */
	if (to_ticks == 0)
		to_ticks = 1;

	c->c_arg = arg;
	c->c_flags &= (~SCTP_CALLOUT_CANCELLED);
	c->c_flags |= (SCTP_CALLOUT_ACTIVE | SCTP_CALLOUT_PENDING);
	c->c_func = ftn;
	c->c_time = target_ticks;
	sctp_binary_heap_push(timers_queue, &c->heap_node);
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": callout %p is scheduled with ticks %" PRIu32 "\n", 
		__func__, ticks, c, target_ticks);
	SCTP_TIMERQ_UNLOCK();
}

int
sctp_os_timer_cancel(sctp_os_timer_t* c) {
	int ret;
	SCTP_TIMERQ_LOCK();
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": request to cancel callout %p\n",
		__func__, ticks, c);
	ret = sctp_os_timer_cancel_impl(c);
	SCTP_TIMERQ_UNLOCK();
	return ret;
}

int
sctp_os_timer_stop(sctp_os_timer_t *c)
{
	SCTP_TIMERQ_LOCK();
	SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": request to stop callout %p\n",
		__func__, ticks, c);
	sctp_os_timer_cancel_impl(c);

	while (c == sctp_os_timer_current) {
		userland_thread_id_t tid;
		sctp_userspace_thread_id(&tid);
		if (sctp_userspace_thread_equal(tid, sctp_os_timer_current_tid)) {
			/*
			 * Deleting the callout from the currently running
			 * callout from the same thread, so just return
			 */
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": self stop %p\n",
				__func__, ticks, c);
			break;
		}
#if defined(__Userspace__)
		sctp_userland_cond_wait(&sctp_os_timer_current_changed, &SCTP_BASE_VAR(timer_mtx));
#endif

		if (c != sctp_os_timer_current) {
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": waited callout completion %p\n", 
				__func__, ticks, c);
		}
	}

	SCTP_TIMERQ_UNLOCK();
	return (1);
}

void
sctp_handle_tick(uint32_t elapsed_ticks)
{
	static uint32_t last_heap_version_reported = 0;

	SCTP_TIMERQ_LOCK();
	/* update our tick count */
	ticks += elapsed_ticks;

	sctp_binary_heap_t* heap = &SCTP_BASE_INFO(timers_queue);
	sctp_binary_heap_node_t* node = NULL;
	while (0 == sctp_binary_heap_peek(heap, &node)) {
		sctp_os_timer_t* c = (sctp_os_timer_t*)node->data;
		if (!SCTP_UINT32_GE(ticks, c->c_time)) {
			if (last_heap_version_reported != sctp_binary_heap_version(heap)) {
				SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": the next soonest callout %p is scheduled at %" PRIu32 ", total scheduled callouts %zu\n",
					__func__, ticks, c, c->c_time, sctp_binary_heap_size(heap));
				last_heap_version_reported = sctp_binary_heap_version(heap);
			}
			// Earliest timer is not ready yet 
			break;
		}
		sctp_binary_heap_remove(heap, node);

		if ((c->c_flags & ((~SCTP_CALLOUT_CANCELLED) | SCTP_CALLOUT_ACTIVE | SCTP_CALLOUT_PENDING)) != 0) {

			void (*c_func)(void*) = c->c_func;
			void* c_arg = c->c_arg;
			uint32_t c_time = c->c_time;
			(void)c_time; // workaround for unused variable warning
			c->c_flags &= ~SCTP_CALLOUT_PENDING;
			sctp_userspace_thread_id(&sctp_os_timer_current_tid);
			sctp_os_timer_current = c;
#if defined(__Userspace__)
			sctp_userland_cond_signal(&sctp_os_timer_current_changed);
#endif
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": callout %p with to_ticks = %" PRIu32 " is about to execute\n", 
				__func__, ticks, sctp_os_timer_current, c_time);
			SCTP_TIMERQ_UNLOCK();
			c_func(c_arg);
			SCTP_TIMERQ_LOCK();
			/* sctp_os_timer_current pointer MUST NOT be dereferenced
			 * after this point, because it's memory might be already
			 * freed by c_func or something else.
			 */
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": callout %p with to_ticks = %" PRIu32 " is executed\n", 
				__func__, ticks, sctp_os_timer_current, c_time);
			sctp_os_timer_current = NULL;
#if defined(__Userspace__)
			sctp_userland_cond_signal(&sctp_os_timer_current_changed);
#endif
		} else {
			SCTPDBG(SCTP_DEBUG_TIMER2, "%s: now=%" PRIu32 ": skipping callout %p with wrong flags %d\n", 
				__func__, ticks, c, c->c_flags);
			KASSERT(0, ("Timer from queue expected to be scheduled and active and not cancelled"));
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
	sctp_userland_cond_destroy(&sctp_os_timer_current_changed);
	return (NULL);
}

void
sctp_start_timer(void)
{
	/*
	 * No need to do SCTP_TIMERQ_LOCK_INIT();
	 * here, it is being done in sctp_pcb_init()
	 */
	sctp_userland_cond_init(&sctp_os_timer_current_changed);
	int rc;
	rc = sctp_userspace_thread_create(&SCTP_BASE_VAR(timer_thread), user_sctp_timer_iterate);
	if (rc) {
		SCTP_PRINTF("ERROR; return code from sctp_thread_create() is %d\n", rc);
	}
}

#endif
