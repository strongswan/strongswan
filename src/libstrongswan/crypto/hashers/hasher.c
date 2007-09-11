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

#include <asn1/oid.h>
#include <crypto/hashers/sha1_hasher.h>
#include <crypto/hashers/sha2_hasher.h>
#include <crypto/hashers/md5_hasher.h>


ENUM(hash_algorithm_names, HASH_UNKNOWN, HASH_SHA512,
	"HASH_UNKNOWN",
	"HASH_MD2",
	"HASH_MD5",
	"HASH_SHA1",
	"HASH_SHA256",
	"HASH_SHA384",
	"HASH_SHA512"
);

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

/*
 * Described in header.
 */
hash_algorithm_t hasher_algorithm_from_oid(int oid)
{
	hash_algorithm_t algorithm;

	switch (oid)
	{
		case OID_MD2:
		case OID_MD2_WITH_RSA:
			algorithm = HASH_MD2;
			break;
		case OID_MD5:
		case OID_MD5_WITH_RSA:
			algorithm = HASH_MD5;
			break;
		case OID_SHA1:
		case OID_SHA1_WITH_RSA:
			algorithm = HASH_SHA1;
			break;
		case OID_SHA256:
		case OID_SHA256_WITH_RSA:
			algorithm = HASH_SHA256;
			break;
		case OID_SHA384:
		case OID_SHA384_WITH_RSA:
			algorithm = HASH_SHA384;
			break;
		case OID_SHA512:
		case OID_SHA512_WITH_RSA:
			algorithm = HASH_SHA512;
			break;
		default:
			algorithm = HASH_UNKNOWN;
	}
	return algorithm;
}
