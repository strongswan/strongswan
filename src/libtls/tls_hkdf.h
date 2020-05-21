/*
 * Copyright (C) 2020 Pascal Knecht
 * Copyright (C) 2020 Méline Sieber
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
 * @defgroup tls_hkdf tls_hkdf
 * @{ @ingroup libtls
 */

#ifndef TLS_HKDF_H_
#define TLS_HKDF_H_

#include <library.h>
#include <crypto/hashers/hasher.h>

typedef struct tls_hkdf_t tls_hkdf_t;

/**
 * TLS HKDF labels
 */
enum tls_hkdf_labels_t {
	TLS_HKDF_EXT_BINDER,
	TLS_HKDF_RES_BINDER,
	TLS_HKDF_C_E_TRAFFIC,
	TLS_HKDF_E_EXP_MASTER,
	TLS_HKDF_C_HS_TRAFFIC,
	TLS_HKDF_S_HS_TRAFFIC,
	TLS_HKDF_C_AP_TRAFFIC,
	TLS_HKDF_S_AP_TRAFFIC,
	TLS_HKDF_EXP_MASTER,
	TLS_HKDF_RES_MASTER,
};

/**
 * TLS HKDF helper functions.
 */
struct tls_hkdf_t {

	/**
	 * Set the (EC)DHE shared secret of this connection.
	 *
	 * @param shared_secret		input key material to use
	 */
	void (*set_shared_secret)(tls_hkdf_t *this, chunk_t shared_secret);

	/**
	 * Allocate secret of the requested label.
	 *
	 * Space for returned secret is allocated and must be freed by the caller.
	 *
	 * @param label				HKDF label of requested secret
	 * @param messages			handshake messages
	 * @param secret			secret will be written into this chunk, if used
	 * @return					TRUE if secrets derived successfully
	 */
	bool (*generate_secret)(tls_hkdf_t *this, enum tls_hkdf_labels_t label,
							chunk_t messages, chunk_t *secret);

	/**
	 * Allocate traffic encryption key bytes.
	 *
	 * Key used to encrypt traffic data as defined in RFC 8446, section 7.3.
	 * Space for returned secret is allocated and must be freed by the caller.
	 *
	 * @param is_server			TRUE if server, FALSE if client derives secret
	 * @param length			key length, in bytes
	 * @param key				secret will be written into this chunk
	 * @return					TRUE if secrets derived successfully
	 */
	bool (*derive_key)(tls_hkdf_t *this, bool is_server, size_t length,
					   chunk_t *key);

	/**
	 * Allocate traffic IV bytes.
	 *
	 * IV used to encrypt traffic data as defined in RFC 8446, section 7.3.
	 * Space for returned secret is allocated and must be freed by the caller.
	 *
	 * @param is_server			TRUE if server, FALSE if client derives secret
	 * @param length			key length, in bytes
	 * @param iv				IV will be written into this chunk
	 * @return					TRUE if secrets derived successfully
	 */
	bool (*derive_iv)(tls_hkdf_t *this, bool is_server, size_t length,
					  chunk_t *iv);

	/**
	 * Allocate finished key bytes.
	 *
	 * Key used to compute Finished messages as defined in RFC 8446,
	 * section 4.4.4. Space for returned secret is allocated and must be freed
	 * by the caller.
	 *
	 * @param is_server			TRUE if server, FALSE if client derives secret
	 * @param finished			key will be written into this chunk
	 * @return					TRUE if secrets derived successfully
	 */
	bool (*derive_finished)(tls_hkdf_t *this, bool is_server,
							chunk_t *finished);

	/**
	 * Destroy a tls_hkdf_t
	 */
	void (*destroy)(tls_hkdf_t *this);
};

/**
 * Create a tls_hkdf instance.
 *
 * @param hash_algorithm	hash algorithm to use
 * @param psk				Pre shared key if available otherwise NULL
 * @return					TLS HKDF helper
 */
tls_hkdf_t *tls_hkdf_create(hash_algorithm_t hash_algorithm, chunk_t psk);

#endif /** TLS_HKDF_H_ @}*/
