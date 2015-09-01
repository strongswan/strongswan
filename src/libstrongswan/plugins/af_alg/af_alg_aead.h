/*
 * Copyright (C) 2015 Tobias Brunner
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
 * @defgroup af_alg_aead af_alg_aead
 * @{ @ingroup af_alg
 */

#ifndef AF_ALG_AEAD_H_
#define AF_ALG_AEAD_H_

typedef struct af_alg_aead_t af_alg_aead_t;

#include <plugins/plugin.h>
#include <crypto/aead.h>

/** Number of aead algorithms */
#define AF_ALG_AEAD 19

/**
 * Implementation of AEAD algorithms using AF_ALG.
 */
struct af_alg_aead_t {

	/**
	 * The aead_t interface.
	 */
	aead_t aead;
};

/**
 * Constructor to create af_alg_aead_t.
 *
 * @param algo			algorithm to implement
 * @param key_size		key size in bytes
 * @param salt_size		size of implicit salt length
 * @return				af_alg_aead_t, NULL if not supported
 */
af_alg_aead_t *af_alg_aead_create(encryption_algorithm_t algo, size_t key_size,
								  size_t salt_size);

/**
 * Probe algorithms and return plugin features.
 *
 * @param features		plugin features to create
 * @param pos			current position in features
 */
void af_alg_aead_probe(plugin_feature_t *features, int *pos);

#endif /** AF_ALG_AEAD_H_ @}*/
