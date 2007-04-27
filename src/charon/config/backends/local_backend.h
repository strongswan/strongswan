/**
 * @file local_backend.h
 *
 * @brief Interface of local_backend_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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
 
#ifndef LOCAL_BACKEND_H_
#define LOCAL_BACKEND_H_

typedef struct local_backend_t local_backend_t;

#include <library.h>
#include <config/backends/writeable_backend.h>

/**
 * @brief An in-memory backend to store configuration information.
 *
 * The local_backend_t stores the configuration in a simple list. It
 * implements both, backend_t and writeable_backend_t.
 *
 * @b Constructors:
 *  - local_backend_create()
 * 
 * @ingroup backends
 */
struct local_backend_t {
	
	/**
	 * Implements writable_backend_t interface
	 */
	writeable_backend_t backend;
};

/**
 * @brief Create a backend_t instance implemented as local backend.
 *
 * @return backend instance.
 * 
 * @ingroup backends
 */
backend_t *backend_create(void);

#endif /* LOCAL_BACKEND_H_ */

