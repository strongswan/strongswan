/*
 * Copyright (C) 2008-2017 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup gmalg_hasher gmalg_hasher
 * @{ @ingroup gmalg_p
 */

#ifndef GMALG_HASHER_H_
#define GMALG_HASHER_H_

typedef struct gmalg_hasher_t gmalg_hasher_t;

#include <crypto/hashers/hasher.h>

#include <openssl/evp.h>

/**
 * Implementation of hashers using OpenSSL.
 */
struct gmalg_hasher_t {

	/**
	 * Implements hasher_t interface.
	 */
	hasher_t hasher;
};

/**
 * Determine EVP_MD for the given hash algorithm
 *
 * @param hash			hash algorithm
 * @return				EVP_MD or NULL if not found/supported
 */
const EVP_MD *gmalg_get_md(hash_algorithm_t hash);

/**
 * Constructor to create gmalg_hasher_t.
 *
 * @param algo			algorithm
 * @return				gmalg_hasher_t, NULL if not supported
 */
gmalg_hasher_t *gmalg_hasher_create(hash_algorithm_t algo);

/**
 * Constructor to create gmalg_hasher_t.
 *
 * @param algo			algorithm
 * @param pub_key		public key
 * @param id			id
 * @return				gmalg_hasher_t, NULL if not supported
 */
gmalg_hasher_t *gmalg_hasher_create_ecc(hash_algorithm_t algo, ECCrefPublicKey *pub_key, chunk_t id);

#endif /** GMALG_HASHER_H_ @}*/
