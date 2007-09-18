/**
 * @file sqlite_backend.h
 *
 * @brief Interface of sqlite_backend_t.
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
 
#ifndef SQLITE_BACKEND_H_
#define SQLITE_BACKEND_H_

typedef struct sqlite_backend_t sqlite_backend_t;

#include <library.h>

#include "backend.h"

/**
 * @brief An SQLite based configuration backend.
 *
 * @b Constructors:
 *  - sqlite_backend_create()
 * 
 * @ingroup backends
 */
struct sqlite_backend_t {
	
	/**
	 * Implements backend_t interface
	 */
	backend_t backend;
};

/**
 * @brief Create a backend_t instance implemented as sqlite backend.
 *
 * @return backend instance
 * 
 * @ingroup backends
 */
backend_t *backend_create(void);

#endif /* SQLITE_BACKEND_H_ */

