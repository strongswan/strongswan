/*
 * Copyright (C) 2008 Tobias Brunner
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
 * @defgroup gmalg_crypter gmalg_crypter
 * @{ @ingroup gmalg_p
 */

#ifndef GMALG_CRYPTER_H_
#define GMALG_CRYPTER_H_

typedef struct gmalg_crypter_t gmalg_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Implementation of crypters using OpenSSL.
 */
struct gmalg_crypter_t {

	/**
	 * Implements crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create gmalg_crypter_t.
 *
 * @param algo			algorithm to implement
 * @param key_size		key size in bytes
 * @return				gmalg_crypter_t, NULL if not supported
 */
gmalg_crypter_t *gmalg_crypter_create(encryption_algorithm_t algo,
												  size_t key_size);

#endif /** GMALG_CRYPTER_H_ @}*/
