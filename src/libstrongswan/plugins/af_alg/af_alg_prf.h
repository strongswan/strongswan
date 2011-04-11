/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup af_alg_prf af_alg_prf
 * @{ @ingroup af_alg
 */

#ifndef AF_ALG_PRF_H_
#define AF_ALG_PRF_H_

typedef struct af_alg_prf_t af_alg_prf_t;

#include <crypto/prfs/prf.h>

/**
 * Implementation of PRFs using AF_ALG.
 */
struct af_alg_prf_t {

	/**
	 * Implements prf_t interface.
	 */
	prf_t prf;
};

/**
 * Creates a new af_alg_prf_t object.
 *
 * @param algo		algorithm to implement
 * @return			af_alg_prf_t object, NULL if hash not supported
 */
af_alg_prf_t *af_alg_prf_create(pseudo_random_function_t algo);

/**
 * Probe algorithms and register af_alg_prf_create().
 *
 * @param plugin		plugin name to register algorithms for
 */
void af_alg_prf_probe(char *plugin);

#endif /** AF_ALG_PRF_H_ @}*/
