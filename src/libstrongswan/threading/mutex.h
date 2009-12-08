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

/**
 * @defgroup mutex mutex
 * @{ @ingroup threading
 */

#ifndef THREADING_MUTEX_H_
#define THREADING_MUTEX_H_

typedef struct mutex_t mutex_t;
typedef enum mutex_type_t mutex_type_t;

#include "condvar.h"

#ifdef __APPLE__
/* on Mac OS X 10.5 several system calls we use are no cancellation points.
 * fortunately, select isn't one of them, so we wrap some of the others with
 * calls to select(2).
 */
#include <sys/socket.h>
#include <sys/select.h>

#define WRAP_WITH_SELECT(func, socket, ...)\
	fd_set rfds; FD_ZERO(&rfds); FD_SET(socket, &rfds);\
	if (select(socket + 1, &rfds, NULL, NULL, NULL) <= 0) { return -1; }\
	return func(socket, __VA_ARGS__)

static inline int cancellable_accept(int socket, struct sockaddr *address,
									 socklen_t *address_len)
{
	WRAP_WITH_SELECT(accept, socket, address, address_len);
}
#define accept cancellable_accept
static inline int cancellable_recvfrom(int socket, void *buffer, size_t length,
				int flags, struct sockaddr *address, socklen_t *address_len)
{
	WRAP_WITH_SELECT(recvfrom, socket, buffer, length, flags, address, address_len);
}
#define recvfrom cancellable_recvfrom
#endif /* __APPLE__ */

/**
 * Type of mutex.
 */
enum mutex_type_t {
	/** default mutex */
	MUTEX_TYPE_DEFAULT	= 0,
	/** allow recursive locking of the mutex */
	MUTEX_TYPE_RECURSIVE	= 1,
};

/**
 * Mutex wrapper implements simple, portable and advanced mutex functions.
 */
struct mutex_t {

	/**
	 * Acquire the lock to the mutex.
	 */
	void (*lock)(mutex_t *this);

	/**
	 * Release the lock on the mutex.
	 */
	void (*unlock)(mutex_t *this);

	/**
	 * Destroy a mutex instance.
	 */
	void (*destroy)(mutex_t *this);
};

/**
 * Create a mutex instance.
 *
 * @param type		type of mutex to create
 * @return			unlocked mutex instance
 */
mutex_t *mutex_create(mutex_type_t type);

#endif /** THREADING_MUTEX_H_ @} */

