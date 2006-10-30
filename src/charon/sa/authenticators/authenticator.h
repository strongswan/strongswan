/**
 * @file authenticator.h
 *
 * @brief Interface of authenticator_t.
 *
 */

/*
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
 */

#ifndef AUTHENTICATOR_H_
#define AUTHENTICATOR_H_

typedef enum auth_method_t auth_method_t;
typedef struct authenticator_t authenticator_t;

#include <types.h>
#include <sa/ike_sa.h>
#include <encoding/payloads/auth_payload.h>

/**
 * Method to use for authentication.
 *
 * @ingroup authenticator
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
	 * EAP authentication. This value is never negotiated and therefore
	 * a value from private use.
	 */
	AUTH_EAP = 201,
};

/**
 * enum names for auth_method_t.
 *
 * @ingroup authenticator
 */
extern enum_name_t *auth_method_names;

/**
 * @brief Authenticator interface implemented by the various authenticators.
 *
 * Currently the following two AUTH methods are supported:
 *  - shared key message integrity code (AUTH_PSK)
 *  - RSA digital signature (AUTH_RSA)
 *
 * @b Constructors:
 *  - authenticator_create()
 *
 * @ingroup authenticator
 */
struct authenticator_t {

	/**
	 * @brief Verify a received authentication payload.
	 *
	 * @param this 				calling object
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
	 * @brief Build an authentication payload to send to the other peer.
	 *
	 * @param this 				calling object
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
	 * @brief Destroys a authenticator_t object.
	 *
	 * @param this 				calling object
	 */
	void (*destroy) (authenticator_t *this);
};

/**
 * @brief Creates an authenticator for the specified auth method.
 *
 * @param ike_sa		associated ike_sa
 * @param auth_method	authentication method to use for build()/verify()
 *
 * @return				authenticator_t object
 *
 * @ingroup sa
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, auth_method_t auth_method);

#endif /* AUTHENTICATOR_H_ */
