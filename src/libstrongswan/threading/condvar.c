/*
 * Copyright (C) 2008-2009 Tobias Brunner
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

#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include <library.h>
#include <debug.h>

#include "condvar.h"
#include "mutex.h"

typedef struct private_condvar_t private_condvar_t;

/**
 * private data of condvar
 */
struct private_condvar_t {

	/**
	 * public functions
	 */
	condvar_t public;

	/**
	 * wrapped pthread condvar
	 */
	pthread_cond_t condvar;
};

/**
 * Implementation of condvar_t.wait.
 */
static void _wait(private_condvar_t *this, private_mutex_t *mutex)
{
	if (mutex->recursive)
	{
		private_r_mutex_t* recursive = (private_r_mutex_t*)mutex;

		/* mutex owner gets cleared during condvar wait */
		recursive->thread = 0;
		pthread_cond_wait(&this->condvar, &mutex->mutex);
		recursive->thread = pthread_self();
	}
	else
	{
		pthread_cond_wait(&this->condvar, &mutex->mutex);
	}
}

/**
 * Implementation of condvar_t.timed_wait_abs.
 */
static bool timed_wait_abs(private_condvar_t *this, private_mutex_t *mutex,
						   timeval_t time)
{
	struct timespec ts;
	bool timed_out;

	ts.tv_sec = time.tv_sec;
	ts.tv_nsec = time.tv_usec * 1000;

	if (mutex->recursive)
	{
		private_r_mutex_t* recursive = (private_r_mutex_t*)mutex;

		recursive->thread = 0;
		timed_out = pthread_cond_timedwait(&this->condvar, &mutex->mutex,
										   &ts) == ETIMEDOUT;
		recursive->thread = pthread_self();
	}
	else
	{
		timed_out = pthread_cond_timedwait(&this->condvar, &mutex->mutex,
										   &ts) == ETIMEDOUT;
	}
	return timed_out;
}

/**
 * Implementation of condvar_t.timed_wait.
 */
static bool timed_wait(private_condvar_t *this, private_mutex_t *mutex,
					   u_int timeout)
{
	timeval_t tv;
	u_int s, ms;

	time_monotonic(&tv);

	s = timeout / 1000;
	ms = timeout % 1000;

	tv.tv_sec += s;
	tv.tv_usec += ms * 1000;

	if (tv.tv_usec > 1000000 /* 1s */)
	{
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}
	return timed_wait_abs(this, mutex, tv);
}

/**
 * Implementation of condvar_t.signal.
 */
static void _signal(private_condvar_t *this)
{
	pthread_cond_signal(&this->condvar);
}

/**
 * Implementation of condvar_t.broadcast.
 */
static void broadcast(private_condvar_t *this)
{
	pthread_cond_broadcast(&this->condvar);
}

/**
 * Implementation of condvar_t.destroy
 */
static void condvar_destroy(private_condvar_t *this)
{
	pthread_cond_destroy(&this->condvar);
	free(this);
}

/*
 * see header file
 */
condvar_t *condvar_create(condvar_type_t type)
{
	switch (type)
	{
		case CONDVAR_TYPE_DEFAULT:
		default:
		{
			pthread_condattr_t condattr;
			private_condvar_t *this = malloc_thing(private_condvar_t);

			this->public.wait = (void(*)(condvar_t*, mutex_t *mutex))_wait;
			this->public.timed_wait = (bool(*)(condvar_t*, mutex_t *mutex, u_int timeout))timed_wait;
			this->public.timed_wait_abs = (bool(*)(condvar_t*, mutex_t *mutex, timeval_t time))timed_wait_abs;
			this->public.signal = (void(*)(condvar_t*))_signal;
			this->public.broadcast = (void(*)(condvar_t*))broadcast;
			this->public.destroy = (void(*)(condvar_t*))condvar_destroy;

			pthread_condattr_init(&condattr);
#ifdef HAVE_CONDATTR_CLOCK_MONOTONIC
			pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
#endif
			pthread_cond_init(&this->condvar, &condattr);
			pthread_condattr_destroy(&condattr);

			return &this->public;
		}
	}
}

