/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup cmac_prf cmac_prf
 * @{ @ingroup cmac_p
 */

#ifndef PRF_CMAC_H_
#define PRF_CMAC_H_

typedef struct cmac_prf_t cmac_prf_t;

#include <crypto/prfs/prf.h>

/**
 * Implementation of prf_t on CBC block cipher using CMAC, RFC 4493 / RFC 4615.
 *
 * This simply wraps a cmac_t in a prf_t. More a question of
 * interface matching.
 */
struct cmac_prf_t {

	/**
	 * Implements prf_t interface.
	 */
	prf_t prf;
};

/**
 * Creates a new cmac_prf_t object.
 *
 * @param algo		algorithm to implement
 * @return			cmac_prf_t object, NULL if hash not supported
 */
cmac_prf_t *cmac_prf_create(pseudo_random_function_t algo);

#endif /** PRF_CMAC_H_ @}*/
