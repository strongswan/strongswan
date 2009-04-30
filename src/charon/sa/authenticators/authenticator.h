/*
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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

/**
 * @defgroup authenticator authenticator
 * @{ @ingroup authenticators
 */

#ifndef AUTHENTICATOR_H_
#define AUTHENTICATOR_H_

typedef enum auth_method_t auth_method_t;
typedef enum auth_class_t auth_class_t;
typedef struct authenticator_t authenticator_t;

#include <library.h>
#include <config/auth_cfg.h>
#include <sa/ike_sa.h>

/**
 * Method to use for authentication, as defined in IKEv2.
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
};

/**
 * enum names for auth_method_t.
 */
extern enum_name_t *auth_method_names;

/**
 * Class of authentication to use. This is different to auth_method_t in that
 * it does not specify a method, but a class of acceptable methods. The found
 * certificate finally dictates wich method is used.
 */
enum auth_class_t {
	/** any class acceptable */
	AUTH_CLASS_ANY = 0,
	/** authentication using public keys (RSA, ECDSA) */
	AUTH_CLASS_PUBKEY = 1,
	/** authentication using a pre-shared secrets */
	AUTH_CLASS_PSK = 2,
	/** authentication using EAP */
	AUTH_CLASS_EAP = 3,
};

/**
 * enum strings for auth_class_t
 */
extern enum_name_t *auth_class_names;

/**
 * Authenticator interface implemented by the various authenticators.
 *
 * An authenticator implementation handles AUTH and EAP payloads. Received
 * messages are passed to the process() method, to send authentication data
 * the message is passed to the build() method.
 */
struct authenticator_t {

	/**
	 * Process an incoming message using the authenticator.
	 *
	 * @param message		message containing authentication payloads
	 * @return
	 *						- SUCCESS if authentication successful
	 *						- FAILED if authentication failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*process)(authenticator_t *this, message_t *message);
	
	/**
	 * Attach authentication data to an outgoing message.
	 *
	 * @param message		message to add authentication data to
	 * @return
	 *						- SUCCESS if authentication successful
	 *						- FAILED if authentication failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*build)(authenticator_t *this, message_t *message);
	
	/**
	 * Destroy authenticator instance.
	 */
	void (*destroy) (authenticator_t *this);
};

/**
 * Create an authenticator to build signatures.
 *
 * @param ike_sa			associated ike_sa
 * @param cfg				authentication configuration
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_init			sent IKE_SA_INIT message data
 * @return					authenticator, NULL if not supported
 */
authenticator_t *authenticator_create_builder(
									ike_sa_t *ike_sa, auth_cfg_t *cfg,
									chunk_t received_nonce, chunk_t sent_init);

/**
 * Create an authenticator to verify signatures.
 * 
 * @param ike_sa			associated ike_sa
 * @param message			message containing authentication data
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init		received IKE_SA_INIT message data
 * @return					authenticator, NULL if not supported
 */
authenticator_t *authenticator_create_verifier(
									ike_sa_t *ike_sa, message_t *message,
									chunk_t sent_nonce, chunk_t received_init);

#endif /** AUTHENTICATOR_H_ @}*/
