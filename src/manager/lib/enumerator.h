/**
 * @file enumerator.h
 * 
 * @brief Interface of enumerator_t.
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

#ifndef ENUMERATOR_H_
#define ENUMERATOR_H_

#include <library.h>

typedef struct enumerator_t enumerator_t;

/**
 * @brief Enumerate is simpler, but more flexible than iterator.
 */
struct enumerator_t {

	/**
	 * @brief Enumerate collection.
	 *
	 * @param ...		variable argument list of pointers, NULL terminated
	 * @return			TRUE if pointers returned
	 */
	bool (*enumerate)(enumerator_t *this, ...);
		
	/**
     * @brief Destroy a enumerator instance.
     */
    void (*destroy)(enumerator_t *this);
};

#endif /* ENUMERATOR_H_ */
