/*
 * Copyright (C) 2011 Tobias Brunner
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

#include <semaphore.h>

#include <library.h>

#include "semaphore.h"

typedef struct private_semaphore_t private_semaphore_t;

/**
 * private data of a semaphore
 */
struct private_semaphore_t {
	/**
	 * public interface
	 */
	semaphore_t public;

	/**
	 * wrapped POSIX semaphore object
	 */
	sem_t sem;
};

METHOD(semaphore_t, wait_, void,
	private_semaphore_t *this)
{
	sem_wait(&this->sem);
}

METHOD(semaphore_t, timed_wait_abs, bool,
	private_semaphore_t *this, timeval_t tv)
{
	timespec_t ts;

	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	/* there are errors other than ETIMEDOUT possible, but we consider them
	 * all as timeout */
	return sem_timedwait(&this->sem, &ts) == -1;
}

METHOD(semaphore_t, timed_wait, bool,
	private_semaphore_t *this, u_int timeout)
{
	timeval_t tv, add;

	add.tv_sec = timeout / 1000;
	add.tv_usec = (timeout % 1000) * 1000;

	time_monotonic(&tv);
	timeradd(&tv, &add, &tv);

	return timed_wait_abs(this, tv);
}

METHOD(semaphore_t, post, void,
	private_semaphore_t *this)
{
	sem_post(&this->sem);
}

METHOD(semaphore_t, destroy, void,
	private_semaphore_t *this)
{
	sem_destroy(&this->sem);
	free(this);
}

/*
 * Described in header
 */
semaphore_t *semaphore_create(u_int value)
{
	private_semaphore_t *this;

	INIT(this,
		.public = {
			.wait = _wait_,
			.timed_wait = _timed_wait,
			.timed_wait_abs = _timed_wait_abs,
			.post = _post,
			.destroy = _destroy,
		},
	);

	sem_init(&this->sem, 0, value);

	return &this->public;
}

