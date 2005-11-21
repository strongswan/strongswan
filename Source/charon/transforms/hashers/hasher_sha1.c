/**
 * @file hasher_sha1.c
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

#include "hasher_sha1.h"

#include "../../utils/allocator.h"

typedef struct private_hasher_sha1_s private_hasher_sha1_t;

struct private_hasher_sha1_s {
	/**
	 * public interface for this hasher
	 */
	hasher_sha1_t public;	
};





/*
 * Described in header
 */
hasher_sha1_t *hasher_sha1_create()
{
	private_hasher_sha1_t *this = allocator_alloc_thing(private_hasher_sha1_t);
	
	if (this == NULL)
	{
		return NULL;	
	}
	
	return &(this->public);
}





