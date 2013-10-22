/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "test_suite.h"

#include <sched.h>
#include <unistd.h>

#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <threading/thread_value.h>

/*******************************************************************************
 * recursive mutex test
 */

#define THREADS 20

/**
 * Thread barrier data
 */
typedef struct {
	mutex_t *mutex;
	condvar_t *cond;
	int count;
	int current;
	bool active;
} barrier_t;

/**
 * Create a thread barrier for count threads
 */
static barrier_t* barrier_create(int count)
{
	barrier_t *this;

	INIT(this,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.cond = condvar_create(CONDVAR_TYPE_DEFAULT),
		.count = count,
	);

	return this;
}

/**
 * Destroy a thread barrier
 */
static void barrier_destroy(barrier_t *this)
{
	this->mutex->destroy(this->mutex);
	this->cond->destroy(this->cond);
	free(this);
}

/**
 * Wait to have configured number of threads in barrier
 */
static bool barrier_wait(barrier_t *this)
{
	bool winner = FALSE;

	this->mutex->lock(this->mutex);
	if (!this->active)
	{	/* first, reset */
		this->active = TRUE;
		this->current = 0;
	}

	this->current++;
	while (this->current < this->count)
	{
		this->cond->wait(this->cond, this->mutex);
	}
	if (this->active)
	{	/* first, win */
		winner = TRUE;
		this->active = FALSE;
	}
	this->mutex->unlock(this->mutex);
	this->cond->broadcast(this->cond);
	sched_yield();

	return winner;
}

/**
 * Barrier for some tests
 */
static barrier_t *barrier;

/**
 * A mutex for tests requiring one
 */
static mutex_t *mutex;

/**
 * A condvar for tests requiring one
 */
static condvar_t *condvar;

/**
 * A counter for signaling
 */
static int sigcount;

static void *mutex_run(void *data)
{
	int locked = 0;
	int i;

	/* wait for all threads before getting in action */
	barrier_wait(barrier);

	for (i = 0; i < 100; i++)
	{
		mutex->lock(mutex);
		mutex->lock(mutex);
		mutex->lock(mutex);
		locked++;
		sched_yield();
		if (locked > 1)
		{
			fail("two threads locked the mutex concurrently");
		}
		locked--;
		mutex->unlock(mutex);
		mutex->unlock(mutex);
		mutex->unlock(mutex);
	}
	return NULL;
}

START_TEST(test_mutex)
{
	thread_t *threads[THREADS];
	int i;

	barrier = barrier_create(THREADS);
	mutex = mutex_create(MUTEX_TYPE_RECURSIVE);

	for (i = 0; i < 10; i++)
	{
		mutex->lock(mutex);
		mutex->unlock(mutex);
	}
	for (i = 0; i < 10; i++)
	{
		mutex->lock(mutex);
	}
	for (i = 0; i < 10; i++)
	{
		mutex->unlock(mutex);
	}

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(mutex_run, NULL);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}

	mutex->destroy(mutex);
	barrier_destroy(barrier);
}
END_TEST

static void *condvar_run(void *data)
{
	mutex->lock(mutex);
	sigcount++;
	condvar->signal(condvar);
	mutex->unlock(mutex);
	return NULL;
}

START_TEST(test_condvar)
{
	thread_t *threads[THREADS];
	int i;

	mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	sigcount = 0;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(condvar_run, NULL);
	}

	mutex->lock(mutex);
	while (sigcount < THREADS)
	{
		condvar->wait(condvar, mutex);
	}
	mutex->unlock(mutex);

	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}

	mutex->destroy(mutex);
	condvar->destroy(condvar);
}
END_TEST

static void *condvar_recursive_run(void *data)
{
	mutex->lock(mutex);
	mutex->lock(mutex);
	mutex->lock(mutex);
	sigcount++;
	condvar->signal(condvar);
	mutex->unlock(mutex);
	mutex->unlock(mutex);
	mutex->unlock(mutex);
	return NULL;
}

START_TEST(test_condvar_recursive)
{
	thread_t *threads[THREADS];
	int i;

	mutex = mutex_create(MUTEX_TYPE_RECURSIVE);
	condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	sigcount = 0;

	mutex->lock(mutex);

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(condvar_recursive_run, NULL);
	}

	mutex->lock(mutex);
	mutex->lock(mutex);
	while (sigcount < THREADS)
	{
		condvar->wait(condvar, mutex);
	}
	mutex->unlock(mutex);
	mutex->unlock(mutex);
	mutex->unlock(mutex);

	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}

	mutex->destroy(mutex);
	condvar->destroy(condvar);
}
END_TEST

static void *condvar_run_broad(void *data)
{
	mutex->lock(mutex);
	while (sigcount < 0)
	{
		condvar->wait(condvar, mutex);
	}
	mutex->unlock(mutex);
	return NULL;
}

START_TEST(test_condvar_broad)
{
	thread_t *threads[THREADS];
	int i;

	mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	sigcount = 0;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(condvar_run_broad, NULL);
	}

	sched_yield();

	mutex->lock(mutex);
	sigcount = 1;
	condvar->broadcast(condvar);
	mutex->unlock(mutex);

	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}

	mutex->destroy(mutex);
	condvar->destroy(condvar);
}
END_TEST

START_TEST(test_condvar_timed)
{
	thread_t *thread;
	timeval_t start, end, diff = { .tv_usec = 50000 };

	mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	sigcount = 0;

	mutex->lock(mutex);
	while (TRUE)
	{
		time_monotonic(&start);
		if (condvar->timed_wait(condvar, mutex, diff.tv_usec / 1000))
		{
			break;
		}
	}
	time_monotonic(&end);
	mutex->unlock(mutex);
	timersub(&end, &start, &end);
	ck_assert_msg(timercmp(&end, &diff, >), "end: %u.%u, diff: %u.%u",
					end.tv_sec, end.tv_usec, diff.tv_sec, diff.tv_usec);

	thread = thread_create(condvar_run, NULL);

	mutex->lock(mutex);
	while (sigcount == 0)
	{
		ck_assert(!condvar->timed_wait(condvar, mutex, 1000));
	}
	mutex->unlock(mutex);

	thread->join(thread);
	mutex->destroy(mutex);
	condvar->destroy(condvar);
}
END_TEST

START_TEST(test_condvar_timed_abs)
{
	thread_t *thread;
	timeval_t start, end, abso, diff = { .tv_usec = 50000 };

	mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	sigcount = 0;

	mutex->lock(mutex);
	while (TRUE)
	{
		time_monotonic(&start);
		timeradd(&start, &diff, &abso);
		if (condvar->timed_wait_abs(condvar, mutex, abso))
		{
			break;
		}
	}
	time_monotonic(&end);
	mutex->unlock(mutex);
	ck_assert_msg(timercmp(&end, &diff, >), "end: %u.%u, diff: %u.%u",
					end.tv_sec, end.tv_usec, abso.tv_sec, abso.tv_usec);

	thread = thread_create(condvar_run, NULL);

	time_monotonic(&start);
	diff.tv_sec = 1;
	timeradd(&start, &diff, &abso);
	mutex->lock(mutex);
	while (sigcount == 0)
	{
		ck_assert(!condvar->timed_wait_abs(condvar, mutex, abso));
	}
	mutex->unlock(mutex);

	thread->join(thread);
	mutex->destroy(mutex);
	condvar->destroy(condvar);
}
END_TEST

static void *join_run(void *data)
{
	/* force some context switches */
	sched_yield();
	return (void*)((uintptr_t)data + THREADS);
}

START_TEST(test_join)
{
	thread_t *threads[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(join_run, (void*)(uintptr_t)i);
	}
	for (i = 0; i < THREADS; i++)
	{
		ck_assert_int_eq((uintptr_t)threads[i]->join(threads[i]), i + THREADS);
	}
}
END_TEST

static void *exit_join_run(void *data)
{
	sched_yield();
	thread_exit((void*)((uintptr_t)data + THREADS));
	/* not reached */
	ck_assert(FALSE);
	return NULL;
}

START_TEST(test_join_exit)
{
	thread_t *threads[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(exit_join_run, (void*)(uintptr_t)i);
	}
	for (i = 0; i < THREADS; i++)
	{
		ck_assert_int_eq((uintptr_t)threads[i]->join(threads[i]), i + THREADS);
	}
}
END_TEST

static void *detach_run(void *data)
{
	refcount_t *running = (refcount_t*)data;

	ignore_result(ref_put(running));
	return NULL;
}

START_TEST(test_detach)
{
	thread_t *threads[THREADS];
	int i;
	refcount_t running = 0;

	for (i = 0; i < THREADS; i++)
	{
		ref_get(&running);
		threads[i] = thread_create(detach_run, &running);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->detach(threads[i]);
	}
	while (running > 0)
	{
		sched_yield();
	}
	/* no checks done here, but we check that thread state gets cleaned
	 * up with leak detective. */
}
END_TEST

static void *detach_exit_run(void *data)
{
	refcount_t *running = (refcount_t*)data;

	ignore_result(ref_put(running));
	thread_exit(NULL);
	/* not reached */
	ck_assert(FALSE);
	return NULL;
}

START_TEST(test_detach_exit)
{
	thread_t *threads[THREADS];
	int i;
	refcount_t running = 0;

	for (i = 0; i < THREADS; i++)
	{
		ref_get(&running);
		threads[i] = thread_create(detach_exit_run, &running);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->detach(threads[i]);
	}
	while (running > 0)
	{
		sched_yield();
	}
	/* no checks done here, but we check that thread state gets cleaned
	 * up with leak detective. */
}
END_TEST

static void *cancel_run(void *data)
{
	/* default cancellability should be TRUE, so don't change it */
	while (TRUE)
	{
		sleep(10);
	}
	return NULL;
}

START_TEST(test_cancel)
{
	thread_t *threads[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(cancel_run, NULL);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->cancel(threads[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}
}
END_TEST

static void *cancel_onoff_run(void *data)
{
	bool *cancellable = (bool*)data;

	thread_cancelability(FALSE);
	*cancellable = FALSE;

	/* we should not get cancelled here */
	usleep(50000);

	*cancellable = TRUE;
	thread_cancelability(TRUE);

	/* but here */
	while (TRUE)
	{
		sleep(10);
	}
	return NULL;
}

START_TEST(test_cancel_onoff)
{
	thread_t *threads[THREADS];
	bool cancellable[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		cancellable[i] = TRUE;
		threads[i] = thread_create(cancel_onoff_run, &cancellable[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		/* wait until thread has cleared its cancellability */
		while (cancellable[i])
		{
			sched_yield();
		}
		threads[i]->cancel(threads[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert(cancellable[i]);
	}
}
END_TEST

static void *cancel_point_run(void *data)
{
	thread_cancelability(FALSE);
	while (TRUE)
	{
		/* implicitly enables cancellability */
		thread_cancellation_point();
	}
	return NULL;
}

START_TEST(test_cancel_point)
{
	thread_t *threads[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(cancel_point_run, NULL);
	}
	sched_yield();
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->cancel(threads[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}
}
END_TEST

static void cleanup1(void *data)
{
	uintptr_t *value = (uintptr_t*)data;

	ck_assert_int_eq(*value, 1);
	(*value)++;
}

static void cleanup2(void *data)
{
	uintptr_t *value = (uintptr_t*)data;

	ck_assert_int_eq(*value, 2);
	(*value)++;
}

static void cleanup3(void *data)
{
	uintptr_t *value = (uintptr_t*)data;

	ck_assert_int_eq(*value, 3);
	(*value)++;
}

static void *cleanup_run(void *data)
{
	thread_cleanup_push(cleanup3, data);
	thread_cleanup_push(cleanup2, data);
	thread_cleanup_push(cleanup1, data);
	return NULL;
}

START_TEST(test_cleanup)
{
	thread_t *threads[THREADS];
	uintptr_t values[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		values[i] = 1;
		threads[i] = thread_create(cleanup_run, &values[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert_int_eq(values[i], 4);
	}
}
END_TEST

static void *cleanup_exit_run(void *data)
{
	thread_cleanup_push(cleanup3, data);
	thread_cleanup_push(cleanup2, data);
	thread_cleanup_push(cleanup1, data);
	thread_exit(NULL);
	ck_assert(FALSE);
	return NULL;
}

START_TEST(test_cleanup_exit)
{
	thread_t *threads[THREADS];
	uintptr_t values[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		values[i] = 1;
		threads[i] = thread_create(cleanup_exit_run, &values[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert_int_eq(values[i], 4);
	}
}
END_TEST

static void *cleanup_cancel_run(void *data)
{
	thread_cancelability(FALSE);

	thread_cleanup_push(cleanup3, data);
	thread_cleanup_push(cleanup2, data);
	thread_cleanup_push(cleanup1, data);

	thread_cancelability(TRUE);

	while (TRUE)
	{
		sleep(1);
	}
	return NULL;
}

START_TEST(test_cleanup_cancel)
{
	thread_t *threads[THREADS];
	uintptr_t values[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		values[i] = 1;
		threads[i] = thread_create(cleanup_cancel_run, &values[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->cancel(threads[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert_int_eq(values[i], 4);
	}
}
END_TEST

static void *cleanup_pop_run(void *data)
{
	thread_cleanup_push(cleanup3, data);
	thread_cleanup_push(cleanup2, data);
	thread_cleanup_push(cleanup1, data);

	thread_cleanup_push(cleanup2, data);
	thread_cleanup_pop(FALSE);

	thread_cleanup_pop(TRUE);
	return NULL;
}

START_TEST(test_cleanup_pop)
{
	thread_t *threads[THREADS];
	uintptr_t values[THREADS];
	int i;

	for (i = 0; i < THREADS; i++)
	{
		values[i] = 1;
		threads[i] = thread_create(cleanup_pop_run, &values[i]);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert_int_eq(values[i], 4);
	}
}
END_TEST

static thread_value_t *tls[10];

static void *tls_run(void *data)
{
	uintptr_t value = (uintptr_t)data;
	int i, j;

	for (i = 0; i < countof(tls); i++)
	{
		ck_assert(tls[i]->get(tls[i]) == NULL);
	}
	for (i = 0; i < countof(tls); i++)
	{
		tls[i]->set(tls[i], (void*)(value * i));
	}
	for (j = 0; j < 1000; j++)
	{
		for (i = 0; i < countof(tls); i++)
		{
			tls[i]->set(tls[i], (void*)(value * i));
			ck_assert(tls[i]->get(tls[i]) == (void*)(value * i));
		}
		sched_yield();
	}
	for (i = 0; i < countof(tls); i++)
	{
		ck_assert(tls[i]->get(tls[i]) == (void*)(value * i));
	}
	return (void*)(value + 1);
}

START_TEST(test_tls)
{
	thread_t *threads[THREADS];
	int i;

	for (i = 0; i < countof(tls); i++)
	{
		tls[i] = thread_value_create(NULL);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i] = thread_create(tls_run, (void*)(uintptr_t)i);
	}

	ck_assert_int_eq((uintptr_t)tls_run((void*)(uintptr_t)(THREADS + 1)),
					 THREADS + 2);

	for (i = 0; i < THREADS; i++)
	{
		ck_assert_int_eq((uintptr_t)threads[i]->join(threads[i]), i + 1);
	}
	for (i = 0; i < countof(tls); i++)
	{
		tls[i]->destroy(tls[i]);
	}
}
END_TEST

static void tls_cleanup(void *data)
{
	uintptr_t *value = (uintptr_t*)data;

	(*value)--;
}

static void *tls_cleanup_run(void *data)
{
	int i;

	for (i = 0; i < countof(tls); i++)
	{
		tls[i]->set(tls[i], data);
	}
	return NULL;
}

START_TEST(test_tls_cleanup)
{
	thread_t *threads[THREADS];
	uintptr_t values[THREADS], main_value = countof(tls);
	int i;

	for (i = 0; i < countof(tls); i++)
	{
		tls[i] = thread_value_create(tls_cleanup);
	}
	for (i = 0; i < THREADS; i++)
	{
		values[i] = countof(tls);
		threads[i] = thread_create(tls_cleanup_run, &values[i]);
	}

	tls_cleanup_run(&main_value);

	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
		ck_assert_int_eq(values[i], 0);
	}
	for (i = 0; i < countof(tls); i++)
	{
		tls[i]->destroy(tls[i]);
	}
	ck_assert_int_eq(main_value, 0);
}
END_TEST

Suite *threading_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("threading");

	tc = tcase_create("recursive mutex");
	tcase_add_test(tc, test_mutex);
	suite_add_tcase(s, tc);

	tc = tcase_create("condvar");
	tcase_add_test(tc, test_condvar);
	tcase_add_test(tc, test_condvar_recursive);
	tcase_add_test(tc, test_condvar_broad);
	tcase_add_test(tc, test_condvar_timed);
	tcase_add_test(tc, test_condvar_timed_abs);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread joining");
	tcase_add_test(tc, test_join);
	tcase_add_test(tc, test_join_exit);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread detaching");
	tcase_add_test(tc, test_detach);
	tcase_add_test(tc, test_detach_exit);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread cancellation");
	tcase_add_test(tc, test_cancel);
	tcase_add_test(tc, test_cancel_onoff);
	tcase_add_test(tc, test_cancel_point);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread cleanup");
	tcase_add_test(tc, test_cleanup);
	tcase_add_test(tc, test_cleanup_exit);
	tcase_add_test(tc, test_cleanup_cancel);
	tcase_add_test(tc, test_cleanup_pop);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread local storage");
	tcase_add_test(tc, test_tls);
	tcase_add_test(tc, test_tls_cleanup);
	suite_add_tcase(s, tc);

	return s;
}
