/**
 * @file hasher_md5.h
 * 
 * @brief Implementation of hasher_t interface using the
 * md5 algorithm.
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

#ifndef HASHER_MD5_H_
#define HASHER_MD5_H_

#include <transforms/hashers/hasher.h>


/**
 * Object representing the md5 hasher
 * 
 */
typedef struct hasher_md5_s hasher_md5_t;

struct hasher_md5_s {
	
	/**
	 * generic hasher_t interface for this hasher
	 */
	hasher_t hasher_interface;
};

/**
 * Creates a new hasher_md5_t object
 * 
 * @return
 * 							- hasher_md5_t if successfully
 * 							- NULL if out of ressources
 */
hasher_md5_t *hasher_md5_create();

#endif /*HASHER_md5_H_*/
