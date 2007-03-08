/**
 * @file prf.c
 * 
 * @brief Generic constructor for all prf_t
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


#include "prf.h"

#include <crypto/hashers/hasher.h>
#include <crypto/prfs/hmac_prf.h>
#include <crypto/prfs/fips_prf.h>

ENUM_BEGIN(pseudo_random_function_names, PRF_UNDEFINED, PRF_FIPS_DES,
	"PRF_UNDEFINED",
	"PRF_FIPS_SHA1_160",
	"PRF_FIPS_DES");
ENUM_NEXT(pseudo_random_function_names, PRF_HMAC_MD5, PRF_HMAC_SHA2_512, PRF_FIPS_DES,
	"PRF_HMAC_MD5",
	"PRF_HMAC_SHA1",
	"PRF_HMAC_TIGER",
	"PRF_AES128_CBC",
	"PRF_HMAC_SHA2_256",
	"PRF_HMAC_SHA2_384",
	"PRF_HMAC_SHA2_512");
ENUM_END(pseudo_random_function_names, PRF_HMAC_SHA2_512);

/*
 * Described in header.
 */
prf_t *prf_create(pseudo_random_function_t pseudo_random_function)
{
	switch (pseudo_random_function)
	{
		case PRF_HMAC_SHA1:
			return (prf_t*)hmac_prf_create(HASH_SHA1);
		case PRF_HMAC_MD5:
			return (prf_t*)hmac_prf_create(HASH_MD5);
		case PRF_HMAC_SHA2_256:
			return (prf_t*)hmac_prf_create(HASH_SHA256);
		case PRF_HMAC_SHA2_384:
			return (prf_t*)hmac_prf_create(HASH_SHA384);
		case PRF_HMAC_SHA2_512:
			return (prf_t*)hmac_prf_create(HASH_SHA512);
		case PRF_FIPS_SHA1_160:
			return (prf_t*)fips_prf_create(20, g_sha1);
		case PRF_FIPS_DES:
		case PRF_HMAC_TIGER:
		case PRF_AES128_CBC:
		default:
			return NULL;
	}
}
