/**
 * @file prf.c
 * 
 * @brief Generic interface for pseudo-random-functions
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


#include "prf.h"

#include "prf_hmac_sha1.h"


/*
 * Described in header
 */
prf_t *prf_create(pseudo_random_function_t pseudo_random_function, chunk_t key)
{
	switch (pseudo_random_function)
	{
		case PRF_HMAC_SHA1:
		{
			return (prf_t*)prf_hmac_sha1_create(key);
		}
		case PRF_HMAC_MD5:
		case PRF_HMAC_TIGER:
		case PRF_AES128_CBC:
		default:
			return NULL;
	}
}





