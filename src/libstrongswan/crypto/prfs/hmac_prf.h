/**
 * @file hmac_prf.h
 * 
 * @brief Interface of hmac_prf_t.
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

#ifndef PRF_HMAC_H_
#define PRF_HMAC_H_

#include <types.h>
#include <crypto/prfs/prf.h>
#include <crypto/hashers/hasher.h>

typedef struct hmac_prf_t hmac_prf_t;

/**
 * @brief Implementation of prf_t interface using the
 * HMAC algorithm.
 * 
 * This simply wraps a hmac_t in a prf_t. More a question of
 * interface matching.
 * 
 * @b Constructors:
 *  - hmac_prf_create()
 * 
 * @ingroup prfs
 */
struct hmac_prf_t {
	
	/**
	 * Generic prf_t interface for this hmac_prf_t class.
	 */
	prf_t prf_interface;
};

/**
 * @brief Creates a new hmac_prf_t object.
 * 
 * @param hash_algorithm	hmac's hash algorithm
 * @return
 * 							- hmac_prf_t object
 * 							- NULL if hash not supported
 * 
 * @ingroup prfs
 */
hmac_prf_t *hmac_prf_create(hash_algorithm_t hash_algorithm);

#endif /*PRF_HMAC_SHA1_H_*/
