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

#ifndef THREADING_RWLOCK_H_
#define THREADING_RWLOCK_H_

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

	/**
	 * wrapped pthread rwlock
	 */
	pthread_rwlock_t rwlock;

	/**
	 * profiling info, if enabled
	 */
	lock_profile_t profile;
};

#endif /* THREADING_THREADING_H_ */

