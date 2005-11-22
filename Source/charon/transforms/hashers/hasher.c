/**
 * @file hasher.c
 * 
 * @brief Generic interface for hash functions
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


#include "hasher.h"

#include "hasher_sha1.h"



/*
 * Described in header
 */
hasher_t *hasher_create(hash_algorithm_t hash_algorithm)
{
	switch (hash_algorithm)
	{
		case HASH_SHA1:
		{
			return (hasher_t*)hasher_sha1_create();
		}
		case HASH_MD5:
		default:
			return NULL;
	}
}





