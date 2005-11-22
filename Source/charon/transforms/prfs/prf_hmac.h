/**
 * @file prf_hmac.h
 * 
 * @brief Implementation of prf_t interface using the
 * a HMAC algorithm. This simply wraps a hmac in a prf.
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

#ifndef PRF_HMAC_H_
#define PRF_HMAC_H_

#include "prf.h"

#include "../../types.h"
#include "../hashers/hasher.h"

/**
 * Object representing a prf using HMAC
 * 
 */
typedef struct prf_hmac_s prf_hmac_t;

struct prf_hmac_s {
	
	/**
	 * generic prf_t interface for this prf
	 */
	prf_t prf_interface;
};

/**
 * Creates a new prf_hmac_t object
 * 
 * @param hash_algorithm			hmac's hash algorithm
 * @return
 * 									- prf_hmac_t if successfully
 * 									- NULL if out of ressources
 */
prf_hmac_t *prf_hmac_create(hash_algorithm_t hash_algorithm);

#endif /*PRF_HMAC_SHA1_H_*/
