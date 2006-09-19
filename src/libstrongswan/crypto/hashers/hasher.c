/**
 * @file hasher.c
 * 
 * @brief Generic constructor for hasher_t.
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


#include "hasher.h"

#include <crypto/hashers/sha1_hasher.h>
#include <crypto/hashers/sha2_hasher.h>
#include <crypto/hashers/md5_hasher.h>

/**
 * String mappings for hash_algorithm_t.
 */
mapping_t hash_algorithm_m[] = {
	{HASH_MD2,"HASH_MD2"},
	{HASH_MD5,"HASH_MD5"},
	{HASH_SHA1,"HASH_SHA1"},
	{HASH_SHA256,"HASH_SHA256"},
	{HASH_SHA384,"HASH_SHA384"},
	{HASH_SHA512,"HASH_SHA512"},
	{MAPPING_END, NULL}
};

/*
 * Described in header.
 */
hasher_t *hasher_create(hash_algorithm_t hash_algorithm)
{
	switch (hash_algorithm)
	{
		case HASH_SHA1:
		{
			return (hasher_t*)sha1_hasher_create();
		}
		case HASH_SHA256:
		case HASH_SHA384:
		case HASH_SHA512:
		{
			return (hasher_t*)sha2_hasher_create(hash_algorithm);
		}
		case HASH_MD5:
		{
			return (hasher_t*)md5_hasher_create();
		}
		default:
			return NULL;
	}
}
