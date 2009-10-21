/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup simaka_crypto simaka_crypto
 * @{ @ingroup libsimaka
 */

#ifndef SIMAKA_CRYPTO_H_
#define SIMAKA_CRYPTO_H_

#include <library.h>

typedef struct simaka_crypto_t simaka_crypto_t;

/**
 * EAP-SIM/AKA crypto helper and key derivation class.
 */
struct simaka_crypto_t {

	/**
	 * Get the signer to use for AT_MAC calculation/verification.
	 *
	 * @return		signer reference, NULL if no keys have been derived
	 */
	signer_t* (*get_signer)(simaka_crypto_t *this);

	/**
	 * Get the signer to use for AT_ENCR_DATA encryption/decryption.
	 *
	 * @return		crypter reference, NULL if no keys have been derived
	 */
	crypter_t* (*get_crypter)(simaka_crypto_t *this);

	/**
	 * Get the random number generator.
	 *
	 * @return		rng reference
	 */
	rng_t* (*get_rng)(simaka_crypto_t *this);

	/**
	 * Derive keys after full authentication.
	 *
	 * This methods derives the k_encr/k_auth keys and loads them into the
	 * internal crypter/signer instances. The passed data is method specific:
	 * For EAP-SIM, it is "n*Kc|NONCE_MT|Version List|Selected Version", for
	 * EAP-AKA it is "IK|CK".
	 *
	 * @param id	peer identity
	 * @param data	method specific data
	 * @return		allocated MSK value
	 */
	chunk_t (*derive_keys_full)(simaka_crypto_t *this, identification_t *id,
								chunk_t data);

	/**
	 * Destroy a simaka_crypto_t.
	 */
	void (*destroy)(simaka_crypto_t *this);
};

/**
 * Create a simaka_crypto instance.
 *
 * @return		EAP-SIM/AKA crypto instance, NULL if algorithms missing
 */
simaka_crypto_t *simaka_crypto_create();

#endif /* SIMAKA_CRYPTO_ @}*/
