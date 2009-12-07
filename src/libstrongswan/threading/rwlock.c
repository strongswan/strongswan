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

#include <threading.h>
#include <library.h>
#include <debug.h>

#include "rwlock.h"
#include "lock_profiler.h"

/**
 * Implementation of rwlock_t.read_lock
 */
static void read_lock(private_rwlock_t *this)
{
	int err;

	profiler_start(&this->profile);
	err = pthread_rwlock_rdlock(&this->rwlock);
	if (err != 0)
	{
		DBG1("!!! RWLOCK READ LOCK ERROR: %s !!!", strerror(err));
	}
	profiler_end(&this->profile);
}

/**
 * Implementation of rwlock_t.write_lock
 */
static void write_lock(private_rwlock_t *this)
{
	int err;

	profiler_start(&this->profile);
	err = pthread_rwlock_wrlock(&this->rwlock);
	if (err != 0)
	{
		DBG1("!!! RWLOCK WRITE LOCK ERROR: %s !!!", strerror(err));
	}
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
	int err;

	err = pthread_rwlock_unlock(&this->rwlock);
	if (err != 0)
	{
		DBG1("!!! RWLOCK UNLOCK ERROR: %s !!!", strerror(err));
	}
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

