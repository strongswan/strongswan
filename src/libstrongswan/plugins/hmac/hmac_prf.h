/*
 * Copyright (C) 2008 Martin Willi
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

/**
 * @defgroup hmac_prf hmac_prf
 * @{ @ingroup hmac_p
 */

#ifndef PRF_HMAC_H_
#define PRF_HMAC_H_

typedef struct hmac_prf_t hmac_prf_t;

#include <crypto/prfs/prf.h>

/**
 * Implementation of prf_t interface using the HMAC algorithm.
 *
 * This simply wraps a hmac_t in a prf_t. More a question of
 * interface matching.
 */
struct hmac_prf_t {

	/**
	 * Generic prf_t interface for this hmac_prf_t class.
	 */
	prf_t prf_interface;
};

/**
 * Creates a new hmac_prf_t object.
 *
 * @param algo		algorithm to implement
 * @return			hmac_prf_t object, NULL if hash not supported
 */
hmac_prf_t *hmac_prf_create(pseudo_random_function_t algo);

#endif /** PRF_HMAC_SHA1_H_ @}*/
