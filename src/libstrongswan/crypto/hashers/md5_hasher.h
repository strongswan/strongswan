/**
 * @file md5_hasher.h
 * 
 * @brief Interface for md5_hasher_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef MD5_HASHER_H_
#define MD5_HASHER_H_

#include <crypto/hashers/hasher.h>


typedef struct md5_hasher_t md5_hasher_t;

/**
 * @brief Implementation of hasher_t interface using the
 * MD5 algorithm.
 * 
 * @b Constructors:
 * - hasher_create() using HASH_MD5 as algorithm
 * - md5_hasher_create()
 * 
 * @see hasher_t
 * 
 * @ingroup hashers
 */
struct md5_hasher_t {
	
	/**
	 * Generic hasher_t interface for this hasher.
	 */
	hasher_t hasher_interface;
};

/**
 * @brief Creates a new md5_hasher_t.
 * 
 * @return	md5_hasher_t object
 * 
 * @ingroup hashers
 */
md5_hasher_t *md5_hasher_create(void);

#endif /*MD5_HASHER_H_*/
