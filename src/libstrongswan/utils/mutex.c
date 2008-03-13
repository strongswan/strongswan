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
 *
 * $Id$
 */

#include "mutex.h"

#include <library.h>
#include <debug.h>

#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>


typedef struct private_mutex_t private_mutex_t;
typedef struct private_n_mutex_t private_n_mutex_t;
typedef struct private_r_mutex_t private_r_mutex_t;
typedef struct private_condvar_t private_condvar_t;

/**
 * private data of mutex
 */
struct private_mutex_t {

	/**
	 * public functions
	 */
	mutex_t public;
	
	/**
	 * wrapped pthread mutex
	 */
	pthread_mutex_t mutex;
};

/**
 * private data of mutex, extended by recursive locking information
 */
struct private_r_mutex_t {

	/**
	 * public functions
	 */
	private_mutex_t generic;
	
	/**
	 * thread which currently owns mutex
	 */
	pthread_t thread;
	
	/**
	 * times we have locked the lock
	 */
	int times;
};

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
 * Implementation of mutex_t.lock.
 */
static void lock(private_mutex_t *this)
{
	if (pthread_mutex_lock(&this->mutex))
	{
		DBG1("!!!! MUTEX %sLOCK ERROR, your code is buggy !!!", "");
	}
}

/**
 * Implementation of mutex_t.unlock.
 */
static void unlock(private_mutex_t *this)
{
	if (pthread_mutex_unlock(&this->mutex))
	{
		DBG1("!!!! MUTEX %sLOCK ERROR, your code is buggy !!!", "UN");
	}
}

/**
 * Implementation of mutex_t.lock.
 */
static void lock_r(private_r_mutex_t *this)
{
	pthread_t self = pthread_self();

	if (this->thread == self)
	{
		this->times++;
		return;
	}
	lock(&this->generic);
	this->thread = self;
	this->times = 1;
}

/**
 * Implementation of mutex_t.unlock.
 */
static void unlock_r(private_r_mutex_t *this)
{
	if (--this->times == 0)
	{
		this->thread = 0;
		unlock(&this->generic);
	}
}

/**
 * Implementation of mutex_t.destroy
 */
static void mutex_destroy(private_mutex_t *this)
{
	pthread_mutex_destroy(&this->mutex);
	free(this);
}

/*
 * see header file
 */
mutex_t *mutex_create(mutex_type_t type)
{
	switch (type)
	{
		case MUTEX_RECURSIVE:
		{
			private_r_mutex_t *this = malloc_thing(private_r_mutex_t);
	
			this->generic.public.lock = (void(*)(mutex_t*))lock_r;
			this->generic.public.unlock = (void(*)(mutex_t*))unlock_r;
			this->generic.public.destroy = (void(*)(mutex_t*))mutex_destroy;	
	
			pthread_mutex_init(&this->generic.mutex, NULL);
			this->thread = 0;
			this->times = 0;
	
			return &this->generic.public;
		}
		case MUTEX_DEFAULT:
		default:
		{
			private_mutex_t *this = malloc_thing(private_mutex_t);
		
			this->public.lock = (void(*)(mutex_t*))lock;
			this->public.unlock = (void(*)(mutex_t*))unlock;
			this->public.destroy = (void(*)(mutex_t*))mutex_destroy;
		
			pthread_mutex_init(&this->mutex, NULL);
		
			return &this->public;
		}
	}
}

/**
 * Implementation of condvar_t.wait.
 */
static void wait(private_condvar_t *this, private_mutex_t *mutex)
{
	pthread_cond_wait(&this->condvar, &mutex->mutex);
}

/**
 * Implementation of condvar_t.timed_wait.
 */
static bool timed_wait(private_condvar_t *this, private_mutex_t *mutex,
					   u_int timeout)
{
	struct timespec ts;
	struct timeval tv;
	u_int s, ms;
	
	gettimeofday(&tv, NULL);
	
	s = timeout / 1000;
	ms = timeout % 1000;
	
	ts.tv_sec = tv.tv_sec + s;
	ts.tv_nsec = tv.tv_usec * 1000 + ms * 1000000;
	if (ts.tv_nsec > 1000000000 /* 1s */)
	{
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}
	return (pthread_cond_timedwait(&this->condvar, &mutex->mutex,
								   &ts) == ETIMEDOUT);
}

/**
 * Implementation of condvar_t.signal.
 */
static void signal(private_condvar_t *this)
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
		case CONDVAR_DEFAULT:
		default:
		{
			private_condvar_t *this = malloc_thing(private_condvar_t);
		
			this->public.wait = (void(*)(condvar_t*, mutex_t *mutex))wait;
			this->public.timed_wait = (bool(*)(condvar_t*, mutex_t *mutex, u_int timeout))timed_wait;
			this->public.signal = (void(*)(condvar_t*))signal;
			this->public.broadcast = (void(*)(condvar_t*))broadcast;
			this->public.destroy = (void(*)(condvar_t*))condvar_destroy;
		
			pthread_cond_init(&this->condvar, NULL);
		
			return &this->public;
		}
	}
}

