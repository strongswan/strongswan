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

#include <sched.h>
#include <pthread.h>

#include "test_suite.h"

#include <threading/mutex.h>

/*******************************************************************************
 * recursive mutex test
 */

#define THREADS 20

static mutex_t *mutex;

static pthread_barrier_t mutex_barrier;

static int mutex_locked = 0;

static void *mutex_run(void *data)
{
	int i;

	/* wait for all threads before getting in action */
	pthread_barrier_wait(&mutex_barrier);

	for (i = 0; i < 100; i++)
	{
		mutex->lock(mutex);
		mutex->lock(mutex);
		mutex->lock(mutex);
		mutex_locked++;
		sched_yield();
		if (mutex_locked > 1)
		{
			fail("two threads locked the mutex concurrently");
		}
		mutex_locked--;
		mutex->unlock(mutex);
		mutex->unlock(mutex);
		mutex->unlock(mutex);
	}
	return NULL;
}

START_TEST(test_mutex)
{
	pthread_t threads[THREADS];
	int i;

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

	pthread_barrier_init(&mutex_barrier, NULL, THREADS);
	for (i = 0; i < THREADS; i++)
	{
		pthread_create(&threads[i], NULL, mutex_run, NULL);
	}
	for (i = 0; i < THREADS; i++)
	{
		pthread_join(threads[i], NULL);
	}
	pthread_barrier_destroy(&mutex_barrier);

	mutex->destroy(mutex);
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

	return s;
}
