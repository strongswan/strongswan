/*
 * Copyright (C) 2008 Tobias Brunner
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
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "mutex.h"

#include <library.h>
#include <debug.h>

typedef struct private_mutex_t private_mutex_t;
typedef struct private_r_mutex_t private_r_mutex_t;
typedef struct private_condvar_t private_condvar_t;
typedef struct private_rwlock_t private_rwlock_t;

#ifdef LOCK_PROFILER

/**
 * Do not report mutexes with an overall waiting time smaller than this (in us)
 */
#define PROFILE_TRESHHOLD 1000

#include <utils/backtrace.h>

typedef struct lock_profile_t lock_profile_t;

struct lock_profile_t {

	/**
	 * how long threads have waited for the lock in this mutex so far
	 */
	timeval_t waited;
	
	/**
	 * backtrace where mutex has been created
	 */
	backtrace_t *backtrace;
};

/**
 * Print and cleanup mutex profiler
 */
static void profiler_cleanup(lock_profile_t *profile)
{
	if (profile->waited.tv_sec > 0 ||
		profile->waited.tv_usec > PROFILE_TRESHHOLD)
	{
		fprintf(stderr, "%d.%06ds in lock created at:",
				profile->waited.tv_sec, profile->waited.tv_usec);
		profile->backtrace->log(profile->backtrace, stderr);
	}
	profile->backtrace->destroy(profile->backtrace);
}

/**
 * Initialize mutex profiler
 */
static void profiler_init(lock_profile_t *profile)
{
	profile->backtrace = backtrace_create(2);
	timerclear(&profile->waited);
}

#define profiler_start(profile) { \
	struct timeval _start, _end, _diff; \
	time_monotonic(&_start);
	
#define profiler_end(profile) \
	time_monotonic(&_end); \
	timersub(&_end, &_start, &_diff); \
	timeradd(&(profile)->waited, &_diff, &(profile)->waited); }

#else /* !LOCK_PROFILER */

#define lock_profile_t struct {}
#define profiler_cleanup(...) {}
#define profiler_init(...) {}
#define profiler_start(...) {}
#define profiler_end(...) {}

#endif /* LOCK_PROFILER */

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
	
	/**
	 * is this a recursiv emutex, implementing private_r_mutex_t?
	 */
	bool recursive;
	
	/**
	 * profiling info, if enabled
	 */
	lock_profile_t profile;
};

/**
 * private data of mutex, extended by recursive locking information
 */
struct private_r_mutex_t {

	/**
	 * Extends private_mutex_t
	 */
	private_mutex_t generic;
	
	/**
	 * thread which currently owns mutex
	 */
	pthread_t thread;
	
	/**
	 * times we have locked the lock, stored per thread
	 */
	pthread_key_t times;
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
 * private data of rwlock
 */
struct private_rwlock_t {

	/**
	 * public functions
	 */
	rwlock_t public;
	
	/**
	 * wrapped pthread rwlock
	 */
	pthread_rwlock_t rwlock;
	
	/**
	 * profiling info, if enabled
	 */
	lock_profile_t profile;
};

/**
 * Implementation of mutex_t.lock.
 */
static void lock(private_mutex_t *this)
{
	profiler_start(&this->profile);
	if (pthread_mutex_lock(&this->mutex))
	{
		DBG1("!!!! MUTEX %sLOCK ERROR, your code is buggy !!!", "");
	}
	profiler_end(&this->profile);
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
		uintptr_t times;
		
		/* times++ */
		times = (uintptr_t)pthread_getspecific(this->times);
		pthread_setspecific(this->times, (void*)times + 1);
	}
	else
	{
		lock(&this->generic);
		this->thread = self;
		/* times = 1 */
		pthread_setspecific(this->times, (void*)1);
	}
}

/**
 * Implementation of mutex_t.unlock.
 */
static void unlock_r(private_r_mutex_t *this)
{
	uintptr_t times;

	/* times-- */
	times = (uintptr_t)pthread_getspecific(this->times);
	pthread_setspecific(this->times, (void*)--times);
	
	if (times == 0)
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
	profiler_cleanup(&this->profile);
	pthread_mutex_destroy(&this->mutex);
	free(this);
}

/**
 * Implementation of mutex_t.destroy for recursive mutex'
 */
static void mutex_destroy_r(private_r_mutex_t *this)
{
	profiler_cleanup(&this->generic.profile);
	pthread_mutex_destroy(&this->generic.mutex);
	pthread_key_delete(this->times);
	free(this);
}

/*
 * see header file
 */
mutex_t *mutex_create(mutex_type_t type)
{
	switch (type)
	{
		case MUTEX_TYPE_RECURSIVE:
		{
			private_r_mutex_t *this = malloc_thing(private_r_mutex_t);
			
			this->generic.public.lock = (void(*)(mutex_t*))lock_r;
			this->generic.public.unlock = (void(*)(mutex_t*))unlock_r;
			this->generic.public.destroy = (void(*)(mutex_t*))mutex_destroy_r;	
			
			pthread_mutex_init(&this->generic.mutex, NULL);
			pthread_key_create(&this->times, NULL);
			this->generic.recursive = TRUE;
			profiler_init(&this->generic.profile);
			this->thread = 0;
			
			return &this->generic.public;
		}
		case MUTEX_TYPE_DEFAULT:
		default:
		{
			private_mutex_t *this = malloc_thing(private_mutex_t);
		
			this->public.lock = (void(*)(mutex_t*))lock;
			this->public.unlock = (void(*)(mutex_t*))unlock;
			this->public.destroy = (void(*)(mutex_t*))mutex_destroy;
			
			pthread_mutex_init(&this->mutex, NULL);
			this->recursive = FALSE;
			profiler_init(&this->profile);
			
			return &this->public;
		}
	}
}

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

/**
 * Implementation of rwlock_t.read_lock
 */
static void read_lock(private_rwlock_t *this)
{
	profiler_start(&this->profile);
	pthread_rwlock_rdlock(&this->rwlock);
	profiler_end(&this->profile);
}

/**
 * Implementation of rwlock_t.write_lock
 */
static void write_lock(private_rwlock_t *this)
{
	profiler_start(&this->profile);
	pthread_rwlock_wrlock(&this->rwlock);
	profiler_end(&this->profile);
}

/**
 * Implementation of rwlock_t.try_write_lock
 */
static bool try_write_lock(private_rwlock_t *this)
{
	return pthread_rwlock_trywrlock(&this->rwlock) == 0;
}

/**
 * Implementation of rwlock_t.unlock
 */
static void rw_unlock(private_rwlock_t *this)
{
	pthread_rwlock_unlock(&this->rwlock);
}

/**
 * Implementation of rwlock_t.destroy
 */
static void rw_destroy(private_rwlock_t *this)
{
	pthread_rwlock_destroy(&this->rwlock);
	profiler_cleanup(&this->profile);
	free(this);
}

/*
 * see header file
 */
rwlock_t *rwlock_create(rwlock_type_t type)
{
	switch (type)
	{
		case RWLOCK_TYPE_DEFAULT:
		default:
		{
			private_rwlock_t *this = malloc_thing(private_rwlock_t);
			
			this->public.read_lock = (void(*)(rwlock_t*))read_lock;
			this->public.write_lock = (void(*)(rwlock_t*))write_lock;
			this->public.try_write_lock = (bool(*)(rwlock_t*))try_write_lock;
			this->public.unlock = (void(*)(rwlock_t*))rw_unlock;
			this->public.destroy = (void(*)(rwlock_t*))rw_destroy;
			
			pthread_rwlock_init(&this->rwlock, NULL);
			profiler_init(&this->profile);
			
			return &this->public;
		}
	}
}

