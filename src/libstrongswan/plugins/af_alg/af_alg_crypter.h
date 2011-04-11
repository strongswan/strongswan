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
 * @defgroup af_alg_crypter af_alg_crypter
 * @{ @ingroup af_alg
 */

#ifndef AF_ALG_CRYPTER_H_
#define AF_ALG_CRYPTER_H_

typedef struct af_alg_crypter_t af_alg_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Implementation of signers using AF_ALG.
 */
struct af_alg_crypter_t {

	/**
	 * The crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create af_alg_crypter_t.
 *
 * @param algo			algorithm to implement
 * @param key_size		key size in bytes
 * @return				af_alg_crypter_t, NULL if not supported
 */
af_alg_crypter_t *af_alg_crypter_create(encryption_algorithm_t algo,
										size_t key_size);

/**
 * Probe algorithms and register af_alg_crypter_create().
 *
 * @param plugin		plugin name to register algorithms for
 */
void af_alg_crypter_probe(char *plugin);

#endif /** AF_ALG_CRYPTER_H_ @}*/
