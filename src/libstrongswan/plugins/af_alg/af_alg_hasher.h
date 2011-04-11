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
 * @defgroup af_alg_hasher af_alg_hasher
 * @{ @ingroup af_alg
 */

#ifndef af_alg_HASHER_H_
#define af_alg_HASHER_H_

typedef struct af_alg_hasher_t af_alg_hasher_t;

#include <crypto/hashers/hasher.h>

/**
 * Implementation of hashers using AF_ALG.
 */
struct af_alg_hasher_t {

	/**
	 * Implements hasher_t interface.
	 */
	hasher_t hasher;
};

/**
 * Constructor to create af_alg_hasher_t.
 *
 * @param algo			algorithm
 * @return				af_alg_hasher_t, NULL if not supported
 */
af_alg_hasher_t *af_alg_hasher_create(hash_algorithm_t algo);

/**
 * Probe algorithms and register af_alg_hasher_create().
 *
 * @param plugin		plugin name to register algorithms for
 */
void af_alg_hasher_probe(char *plugin);

#endif /** af_alg_HASHER_H_ @}*/
