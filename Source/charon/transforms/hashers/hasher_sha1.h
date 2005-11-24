/**
 * @file hasher_sha1.h
 * 
 * @brief Implementation of hasher_t interface using the
 * SHA1 algorithm.
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

#ifndef HASHER_SHA1_H_
#define HASHER_SHA1_H_

#include <transforms/hashers/hasher.h>


typedef struct hasher_sha1_t hasher_sha1_t;

/**
 * Object representing the sha1 hasher
 * 
 */
struct hasher_sha1_t {
	
	/**
	 * generic hasher_t interface for this hasher
	 */
	hasher_t hasher_interface;
};

/**
 * Creates a new hasher_sha1_t object
 * 
 * @return
 * 							- hasher_sha1_t if successfully
 * 							- NULL if out of ressources
 */
hasher_sha1_t *hasher_sha1_create();

#endif /*HASHER_SHA1_H_*/
