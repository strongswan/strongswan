/*
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

#include <library.h>
#include <threading/mutex.h>

#include <unistd.h>
#include <sched.h>
#include <pthread.h>


static mutex_t *mutex;

static int locked = 0;

static bool failed = FALSE;

static pthread_barrier_t barrier;

static void* run(void* null)
{
	int i;

	/* wait for all threads before getting in action */
	pthread_barrier_wait(&barrier);

	for (i = 0; i < 100; i++)
	{
		mutex->lock(mutex);
		mutex->lock(mutex);
		mutex->lock(mutex);
		locked++;
		sched_yield();
		if (locked > 1)
		{
			failed = TRUE;
		}
		locked--;
		mutex->unlock(mutex);
		mutex->unlock(mutex);
		mutex->unlock(mutex);
	}
	return NULL;
}

#define THREADS 20

/*******************************************************************************
 * mutex test
 ******************************************************************************/
bool test_mutex()
{
	int i;
	pthread_t threads[THREADS];

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

	pthread_barrier_init(&barrier, NULL, THREADS);

	for (i = 0; i < THREADS; i++)
	{
		pthread_create(&threads[i], NULL, run, NULL);
	}
	for (i = 0; i < THREADS; i++)
	{
		pthread_join(threads[i], NULL);
	}
	pthread_barrier_destroy(&barrier);

	mutex->destroy(mutex);

	return !failed;
}

