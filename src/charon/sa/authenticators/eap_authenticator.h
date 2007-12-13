/**
 * @file eap_authenticator.h
 *
 * @brief Interface of eap_authenticator_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef EAP_AUTHENTICATOR_H_
#define EAP_AUTHENTICATOR_H_

typedef struct eap_authenticator_t eap_authenticator_t;

#include <sa/authenticators/authenticator.h>
#include <encoding/payloads/eap_payload.h>

/**
 * @brief Implementation of the authenticator_t interface using AUTH_EAP.
 *
 * Authentication using EAP involves the most complex authenticator. It stays
 * alive over multiple ike_auth transactions and handles multiple EAP
 * messages.
 * EAP authentication must be clearly distinguished between using
 * mutual EAP methods and using methods not providing server authentication.
 * If no mutual authentication is used, the server must prove it's identity
 * by traditional AUTH methods (RSA, psk). Only when the EAP method is mutual,
 * the client should accept an EAP-only authentication.
 * RFC4306 does always use traditional authentiction, EAP only authentication
 * is described in the internet draft draft-eronen-ipsec-ikev2-eap-auth-05.txt.
 *
 * @verbatim
                          ike_sa_init
                   ------------------------->
                   <-------------------------
                 followed by multiple ike_auth:

     +--------+                                +--------+
     |  EAP   |    ID, SA, TS, N(EAP_ONLY)     |  EAP   |
     | client |  --------------------------->  | server |
     |        |          ID, [AUTH,] EAP       |        |  AUTH payload is
     |        |  <---------------------------  |        |  only included if
     |        |              EAP               |        |  authentication
     |        |  --------------------------->  |        |  is not mutual.
     |        |              EAP               |        |
     |        |  <---------------------------  |        |
     |        |              EAP               |        |
     |        |  --------------------------->  |        |
     |        |           EAP(SUCCESS)         |        |
     |        |  <---------------------------  |        |
     |        |              AUTH              |        |  If EAP establishes
     |        |  --------------------------->  |        |  a session key, AUTH
     |        |          AUTH, SA, TS          |        |  payloads use this
     |        |  <---------------------------  |        |  key, not SK_pi/pr
     +--------+                                +--------+

   @endverbatim
 * @b Constructors:
 *  - eap_authenticator_create()
 *  - authenticator_create() using auth_method AUTH_EAP
 *
 * @ingroup authenticators
 */
struct eap_authenticator_t {

	/**
	 * Implemented authenticator_t interface.
	 */
	authenticator_t authenticator_interface;
	
	/**
	 * @brief Check if the EAP method was/is mutual and secure.
	 *
	 * RFC4306 proposes to authenticate the EAP responder (server) by standard
	 * IKEv2 methods (RSA, psk). Not all, but some EAP methods
	 * provide mutual authentication, which would result in a redundant
	 * authentication. If the client supports EAP_ONLY_AUTHENTICATION, and
	 * the the server provides mutual authentication, authentication using
	 * RSA/PSK may be omitted. If the server did not include a traditional
	 * AUTH payload, the client must verify that the server initiated mutual
	 * EAP authentication before it can trust the server.
	 *
	 * @param this	calling object
	 * @return		TRUE, if no AUTH payload required, FALSE otherwise
	 */
	bool (*is_mutual) (eap_authenticator_t* this);
	
	/**
	 * @brief Initiate the EAP exchange.
	 *
	 * The server initiates EAP exchanges, so the client never calls
	 * this method. If initiate() returns NEED_MORE, the EAP authentication
	 * process started. In any case, a payload is created in "out".
	 *
	 * @param this		calling object
	 * @param type		EAP method to use to authenticate client
	 * @param vendor	EAP vendor identifier, if type is vendor specific, or 0
	 * @param out		created initiaal EAP message to send
	 * @return
	 *				- FAILED, if initiation failed
	 *				- NEED_MORE, if more EAP exchanges reqired
	 */
	status_t (*initiate) (eap_authenticator_t* this, eap_type_t type,
						  u_int32_t vendor, eap_payload_t **out);
	
	/**
	 * @brief Process an EAP message.
	 *
	 * After receiving an EAP message "in", the peer/server processes
	 * the payload and creates a reply/subsequent request.
	 * The server side always returns NEED_MORE if another EAP message
	 * is expected from the client, SUCCESS if EAP exchange completed and
	 * "out" is EAP_SUCCES, or FAILED if the EAP exchange failed with
	 * a EAP_FAILURE payload in "out". Anyway, a payload in "out" is always
	 * created.
	 * The peer (client) side only creates a "out" payload if result is
	 * NEED_MORE, a SUCCESS/FAILED is returned whenever a
	 * EAP_SUCCESS/EAP_FAILURE message is received in "in".
	 * If a SUCCESS is returned (on any side), the EAP authentication was
	 * successful and the AUTH payload can be exchanged.
	 *
	 * @param this	calling object
	 * @param in	received EAP message
	 * @param out	created EAP message to send
	 * @return
	 *				- FAILED, if authentication/EAP exchange failed
	 *				- SUCCESS, if authentication completed
	 *				- NEED_MORE, if more EAP exchanges reqired
	 */
	status_t (*process) (eap_authenticator_t* this,
						 eap_payload_t *in, eap_payload_t **out);
};

/**
 * @brief Creates an authenticator for AUTH_EAP.
 *
 * @param ike_sa		associated ike_sa
 * @return				eap_authenticator_t object
 *
 * @ingroup authenticators
 */
eap_authenticator_t *eap_authenticator_create(ike_sa_t *ike_sa);

#endif /* EAP_AUTHENTICATOR_H_ */
