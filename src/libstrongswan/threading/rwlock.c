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

#include <library.h>
#include <debug.h>

#include "rwlock.h"
#include "condvar.h"
#include "mutex.h"
#include "lock_profiler.h"

typedef struct private_rwlock_t private_rwlock_t;

/**
 * private data of rwlock
 */
struct private_rwlock_t {

	/**
	 * public functions
	 */
	rwlock_t public;

#ifdef HAVE_PTHREAD_RWLOCK_INIT

	/**
	 * wrapped pthread rwlock
	 */
	pthread_rwlock_t rwlock;

#else

	/**
	 * mutex to emulate a native rwlock
	 */
	mutex_t *mutex;

	/**
	 * condvar to handle writers
	 */
	condvar_t *writers;

	/**
	 * condvar to handle readers
	 */
	condvar_t *readers;

	/**
	 * number of waiting writers
	 */
	u_int waiting_writers;

	/**
	 * number of readers holding the lock
	 */
	u_int reader_count;

	/**
	 * current writer thread, if any
	 */
	pthread_t writer;

#endif /* HAVE_PTHREAD_RWLOCK_INIT */

	/**
	 * profiling info, if enabled
	 */
	lock_profile_t profile;
};


#ifdef HAVE_PTHREAD_RWLOCK_INIT

METHOD(rwlock_t, read_lock, void,
	private_rwlock_t *this)
{
	int err;

	profiler_start(&this->profile);
	err = pthread_rwlock_rdlock(&this->rwlock);
	if (err != 0)
	{
		DBG1(DBG_LIB, "!!! RWLOCK READ LOCK ERROR: %s !!!", strerror(err));
	}
	profiler_end(&this->profile);
}

METHOD(rwlock_t, write_lock, void,
	private_rwlock_t *this)
{
	int err;

	profiler_start(&this->profile);
	err = pthread_rwlock_wrlock(&this->rwlock);
	if (err != 0)
	{
		DBG1(DBG_LIB, "!!! RWLOCK WRITE LOCK ERROR: %s !!!", strerror(err));
	}
	profiler_end(&this->profile);
}

METHOD(rwlock_t, try_write_lock, bool,
	private_rwlock_t *this)
{
	return pthread_rwlock_trywrlock(&this->rwlock) == 0;
}

METHOD(rwlock_t, unlock, void,
	private_rwlock_t *this)
{
	int err;

	err = pthread_rwlock_unlock(&this->rwlock);
	if (err != 0)
	{
		DBG1(DBG_LIB, "!!! RWLOCK UNLOCK ERROR: %s !!!", strerror(err));
	}
}

METHOD(rwlock_t, destroy, void,
	private_rwlock_t *this)
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
			private_rwlock_t *this;

			INIT(this,
				.public = {
					.read_lock = _read_lock,
					.write_lock = _write_lock,
					.try_write_lock = _try_write_lock,
					.unlock = _unlock,
					.destroy = _destroy,
				}
			);

			pthread_rwlock_init(&this->rwlock, NULL);
			profiler_init(&this->profile);

			return &this->public;
		}
	}
}

#else /* HAVE_PTHREAD_RWLOCK_INIT */

/**
 * This implementation of the rwlock_t interface uses mutex_t and condvar_t
 * primitives, if the pthread_rwlock_* group of functions is not available.
 *
 * The following constraints are enforced:
 *   - Multiple readers can hold the lock at the same time.
 *   - Only a single writer can hold the lock at any given time.
 *   - A writer must block until all readers have released the lock before
 *     obtaining the lock exclusively.
 *   - Readers that arrive while a writer is waiting to acquire the lock will
 *     block until after the writer has obtained and released the lock.
 * These constraints allow for read sharing, prevent write sharing, prevent
 * read-write sharing and prevent starvation of writers by a steady stream
 * of incoming readers. Reader starvation is not prevented (this could happen
 * if there are more writers than readers).
 *
 * The implementation does not support recursive locking and readers must not
 * acquire the lock exclusively at the same time and vice-versa (this is not
 * checked or enforced so behave yourself to prevent deadlocks).
 */

METHOD(rwlock_t, read_lock, void,
	private_rwlock_t *this)
{
	profiler_start(&this->profile);
	this->mutex->lock(this->mutex);
	while (this->writer || this->waiting_writers)
	{
		this->readers->wait(this->readers, this->mutex);
	}
	this->reader_count++;
	profiler_end(&this->profile);
	this->mutex->unlock(this->mutex);
}

METHOD(rwlock_t, write_lock, void,
	private_rwlock_t *this)
{
	profiler_start(&this->profile);
	this->mutex->lock(this->mutex);
	this->waiting_writers++;
	while (this->writer || this->reader_count)
	{
		this->writers->wait(this->writers, this->mutex);
	}
	this->waiting_writers--;
	this->writer = pthread_self();
	profiler_end(&this->profile);
	this->mutex->unlock(this->mutex);
}

METHOD(rwlock_t, try_write_lock, bool,
	private_rwlock_t *this)
{
	bool res = FALSE;
	this->mutex->lock(this->mutex);
	if (!this->writer && !this->reader_count)
	{
		res = TRUE;
		this->writer = pthread_self();
	}
	this->mutex->unlock(this->mutex);
	return res;
}

METHOD(rwlock_t, unlock, void,
	private_rwlock_t *this)
{
	this->mutex->lock(this->mutex);
	if (this->writer == pthread_self())
	{
		this->writer = 0;
		if (this->waiting_writers)
		{
			this->writers->signal(this->writers);
		}
		else
		{
			this->readers->broadcast(this->readers);
		}
	}
	else
	{
		this->reader_count--;
		if (!this->reader_count)
		{
			this->writers->signal(this->writers);
		}
	}
	this->mutex->unlock(this->mutex);
}

METHOD(rwlock_t, destroy, void,
	private_rwlock_t *this)
{
	this->mutex->destroy(this->mutex);
	this->writers->destroy(this->writers);
	this->readers->destroy(this->readers);
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
			private_rwlock_t *this;

			INIT(this,
				.public = {
					.read_lock = _read_lock,
					.write_lock = _write_lock,
					.try_write_lock = _try_write_lock,
					.unlock = _unlock,
					.destroy = _destroy,
				},
				.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
				.writers = condvar_create(CONDVAR_TYPE_DEFAULT),
				.readers = condvar_create(CONDVAR_TYPE_DEFAULT),
			);

			profiler_init(&this->profile);

			return &this->public;
		}
	}
}

#endif /* HAVE_PTHREAD_RWLOCK_INIT */

