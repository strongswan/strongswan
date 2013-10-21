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

#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>

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

static void *mutex_run(void *data)
{
	mutex_t *mutex = (mutex_t*)data;
	static int locked = 0;
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
	mutex_t *mutex;
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
		threads[i] = thread_create(mutex_run, mutex);
	}
	for (i = 0; i < THREADS; i++)
	{
		threads[i]->join(threads[i]);
	}

	mutex->destroy(mutex);
	barrier_destroy(barrier);
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

Suite *threading_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("threading");

	tc = tcase_create("recursive mutex");
	tcase_add_test(tc, test_mutex);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread joining");
	tcase_add_test(tc, test_join);
	suite_add_tcase(s, tc);

	tc = tcase_create("thread detaching");
	tcase_add_test(tc, test_detach);
	suite_add_tcase(s, tc);

	return s;
}
