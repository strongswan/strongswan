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
 * @defgroup tls_crypto tls_crypto
 * @{ @ingroup tls
 */

#ifndef TLS_CRYPTO_H_
#define TLS_CRYPTO_H_

typedef struct tls_crypto_t tls_crypto_t;

#include "tls.h"
#include "tls_prf.h"

#include <credentials/keys/private_key.h>

/**
 * TLS crypto helper functions.
 */
struct tls_crypto_t {

	/**
	 * Get a list of supported TLS cipher suites.
	 *
	 * @param suites		list of suites, points to internal data
	 * @return				number of suites returned
	 */
	int (*get_cipher_suites)(tls_crypto_t *this, tls_cipher_suite_t **suites);

	/**
	 * Select and store a cipher suite from a given list of candidates.
	 *
	 * @param suites		list of candidates to select from
	 * @param count			number of suites
	 * @return				selected suite, 0 if none acceptable
	 */
	tls_cipher_suite_t (*select_cipher_suite)(tls_crypto_t *this,
										tls_cipher_suite_t *suites, int count);

	/**
	 * Store exchanged handshake data, used for cryptographic operations.
	 *
	 * @param type			handshake sub type
	 * @param data			data to append to handshake buffer
	 */
	void (*append_handshake)(tls_crypto_t *this,
							 tls_handshake_type_t type, chunk_t data);

	/**
	 * Create a signature of the handshake data using a given private key.
	 *
	 * @param key			private key to use for signature
	 * @param sig			allocated signature
	 * @return				TRUE if signature create successfully
	 */
	bool (*sign_handshake)(tls_crypto_t *this, private_key_t *key, chunk_t *sig);

	/**
	 * Calculate the data of a TLS finished message.
	 *
	 * @param label			ASCII label to use for calculation
	 * @param out			buffer to write finished data to
	 * @return				TRUE if calculation successful
	 */
	bool (*calculate_finished)(tls_crypto_t *this, char *label, char out[12]);

	/**
	 * Derive the master secret, MAC and encryption keys.
	 *
	 * @param premaster		premaster secret
	 * @param client_random	random data from client hello
	 * @param server_random	random data from server hello
	 */
	void (*derive_secrets)(tls_crypto_t *this, chunk_t premaster,
						   chunk_t client_random, chunk_t server_random);

	/**
	 * Change the cipher used at protection layer.
	 *
	 * @param inbound		TRUE to change inbound cipher, FALSE for outbound
	 */
	void (*change_cipher)(tls_crypto_t *this, bool inbound);

	/**
	 * Derive the EAP-TLS MSK.
	 *
	 * @param client_random	random data from client hello
	 * @param server_random	random data from server hello
	 */
	void (*derive_eap_msk)(tls_crypto_t *this,
						   chunk_t client_random, chunk_t server_random);

	/**
	 * Get the MSK to use in EAP-TLS.
	 *
	 * @return				MSK, points to internal data
	 */
	chunk_t (*get_eap_msk)(tls_crypto_t *this);

	/**
	 * Destroy a tls_crypto_t.
	 */
	void (*destroy)(tls_crypto_t *this);
};

/**
 * Create a tls_crypto instance.
 */
tls_crypto_t *tls_crypto_create(tls_t *tls);

#endif /** TLS_CRYPTO_H_ @}*/
