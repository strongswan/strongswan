/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 *
 * $Id$
 */

/**
 * @defgroup authenticator authenticator
 * @{ @ingroup authenticators
 */

#ifndef AUTHENTICATOR_H_
#define AUTHENTICATOR_H_

typedef enum auth_method_t auth_method_t;
typedef struct authenticator_t authenticator_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <config/peer_cfg.h>
#include <encoding/payloads/auth_payload.h>

/**
 * Method to use for authentication.
 */
enum auth_method_t {
	/**
	 * Computed as specified in section 2.15 of RFC using 
	 * an RSA private key over a PKCS#1 padded hash.
	 */
	AUTH_RSA = 1,
	
	/**
	 * Computed as specified in section 2.15 of RFC using the 
	 * shared key associated with the identity in the ID payload 
	 * and the negotiated prf function
	 */
	AUTH_PSK = 2,
	
	/**
	 * Computed as specified in section 2.15 of RFC using a 
	 * DSS private key over a SHA-1 hash.
	 */
	AUTH_DSS = 3,
	
	/**
	 * ECDSA with SHA-256 on the P-256 curve as specified in RFC 4754
	 */
	AUTH_ECDSA_256 = 9,
	
	/**
	 * ECDSA with SHA-384 on the P-384 curve as specified in RFC 4754
	 */
	AUTH_ECDSA_384 = 10,
	
	/**
	 * ECDSA with SHA-512 on the P-521 curve as specified in RFC 4754
	 */
	AUTH_ECDSA_521 = 11,
	
	/**
	 * EAP authentication. This value is never negotiated and therefore
	 * a value from private use.
	 */
	AUTH_EAP = 201,
};

/**
 * enum names for auth_method_t.
 */
extern enum_name_t *auth_method_names;

/**
 * Authenticator interface implemented by the various authenticators.
 *
 * Currently the following two AUTH methods are supported:
 *  - shared key message integrity code
 *  - RSA digital signature
 *  - ECDSA is supported using OpenSSL
 */
struct authenticator_t {

	/**
	 * Verify a received authentication payload.
	 *
	 * @param ike_sa_init		binary representation of received ike_sa_init
	 * @param my_nonce			the sent nonce
	 * @param auth_payload		authentication payload to verify
	 *
	 * @return
	 *							- SUCCESS,
	 *							- FAILED if verification failed
	 *							- INVALID_ARG if auth_method does not match
	 *							- NOT_FOUND if credentials not found
	 */
	status_t (*verify) (authenticator_t *this, chunk_t ike_sa_init,
						chunk_t my_nonce, auth_payload_t *auth_payload);

	/**
	 * Build an authentication payload to send to the other peer.
	 *
	 * @param ike_sa_init		binary representation of sent ike_sa_init
	 * @param other_nonce		the received nonce
	 * @param[out] auth_payload	the resulting authentication payload
	 *
	 * @return
	 *							- SUCCESS,
	 *							- NOT_FOUND if the data for AUTH method could not be found
	 */
	status_t (*build) (authenticator_t *this, chunk_t ike_sa_init,
					   chunk_t other_nonce, auth_payload_t **auth_payload);

	/**
	 * Destroys a authenticator_t object.
	 */
	void (*destroy) (authenticator_t *this);
};

/**
 * Creates an authenticator for the specified auth method (as configured).
 *
 * @param ike_sa		associated ike_sa
 * @param auth_method	authentication method to use for build()/verify()
 *
 * @return				authenticator_t object
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, config_auth_method_t auth_method);

/**
 * Creates an authenticator from the given auth payload.
 * 
 * @param ike_sa		associated ike_sa
 * @param auth_payload	auth payload
 * 
 * @return				authenticator_t object
 */
authenticator_t *authenticator_create_from_auth_payload(ike_sa_t *ike_sa, auth_payload_t *auth_payload);

#endif /* AUTHENTICATOR_H_ @} */
