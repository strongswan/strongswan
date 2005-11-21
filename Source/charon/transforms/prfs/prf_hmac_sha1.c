/**
 * @file prf_hmac_sha1.h
 * 
 * @brief Implementation of prf_t interface using the
 * HMAC SHA1 algorithm.
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

#include "prf_hmac_sha1.h"

#include "../../utils/allocator.h"

typedef struct private_prf_hmac_sha1_s private_prf_hmac_sha1_t;

struct private_prf_hmac_sha1_s {
	/**
	 * public interface for this prf
	 */
	prf_hmac_sha1_t public;	
};








/*
 * Described in header
 */
prf_hmac_sha1_t *prf_hmac_sha1_create(chunk_t key)
{
	private_prf_hmac_sha1_t *this = allocator_alloc_thing(private_prf_hmac_sha1_t);
	
	if (this == NULL)
	{
		return NULL;	
	}
	
	return &(this->public);
	
}





