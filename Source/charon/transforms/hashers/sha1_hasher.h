/**
 * @file sha1_hasher.h
 * 
 * @brief Interface of sha1_hasher_t
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef SHA1_HASHER_H_
#define SHA1_HASHER_H_

#include <transforms/hashers/hasher.h>


typedef struct sha1_hasher_t sha1_hasher_t;

/**
 * @brief Implementation of hasher_t interface using the
 * SHA1 algorithm.
 * 
 * @ingroup hashers
 */
struct sha1_hasher_t {
	
	/**
	 * generic hasher_t interface for this hasher
	 */
	hasher_t hasher_interface;
};

/**
 * @brief Creates a new sha1_hasher_t.
 * 
 * @return	sha1_hasher_t object
 * 
 * @ingroup hashers
 */
sha1_hasher_t *sha1_hasher_create();

#endif /*SHA1_HASHER_H_*/
