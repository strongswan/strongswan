/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup xcbc_prf xcbc_prf
 * @{ @ingroup xcbc_p
 */

#ifndef PRF_XCBC_H_
#define PRF_XCBC_H_

typedef struct xcbc_prf_t xcbc_prf_t;

#include <crypto/prfs/prf.h>

/**
 * Implementation of prf_t on CBC block cipher using XCBC, RFC3664/RFC4434.
 *
 * This simply wraps a xcbc_t in a prf_t. More a question of
 * interface matching.
 */
struct xcbc_prf_t {

	/**
	 * Generic prf_t interface for this xcbc_prf_t class.
	 */
	prf_t prf_interface;
};

/**
 * Creates a new xcbc_prf_t object.
 *
 * @param algo		algorithm to implement
 * @return			xcbc_prf_t object, NULL if hash not supported
 */
xcbc_prf_t *xcbc_prf_create(pseudo_random_function_t algo);

#endif /** PRF_XCBC_SHA1_H_ @}*/
