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
 *
 * $Id$
 */

/**
 * @defgroup eap_method eap_method
 * @{ @ingroup eap
 */

#ifndef EAP_METHOD_H_
#define EAP_METHOD_H_

typedef struct eap_method_t eap_method_t;
typedef enum eap_role_t eap_role_t;
typedef enum eap_type_t eap_type_t;
typedef enum eap_code_t eap_code_t;

#include <library.h>
#include <utils/identification.h>
#include <encoding/payloads/eap_payload.h>

/**
 * Role of an eap_method, SERVER or PEER (client)
 */
enum eap_role_t {
	EAP_SERVER,
	EAP_PEER,
};
/**
 * enum names for eap_role_t.
 */
extern enum_name_t *eap_role_names;

/**
 * EAP types, defines the EAP method implementation
 */
enum eap_type_t {
	EAP_IDENTITY = 1,
	EAP_NOTIFICATION = 2,
	EAP_NAK = 3,
	EAP_MD5 = 4,
	EAP_OTP = 5,
	EAP_GTC = 6,
	EAP_SIM = 18,
	EAP_AKA = 23,
	EAP_EXPANDED = 254,
	EAP_EXPERIMENTAL = 255,
};

/**
 * enum names for eap_type_t.
 */
extern enum_name_t *eap_type_names;

/**
 * EAP code, type of an EAP message
 */
enum eap_code_t {
	EAP_REQUEST = 1,
	EAP_RESPONSE = 2,
	EAP_SUCCESS = 3,
	EAP_FAILURE = 4,
};

/**
 * enum names for eap_code_t.
 */
extern enum_name_t *eap_code_names;


/**
 * Interface of an EAP method for server and client side.
 *
 * An EAP method initiates an EAP exchange and processes requests and
 * responses. An EAP method may need multiple exchanges before succeeding, and
 * the eap_authentication may use multiple EAP methods to authenticate a peer.
 * To accomplish these requirements, all EAP methods have their own
 * implementation while the eap_authenticatior uses one or more of these
 * EAP methods. Sending of EAP(SUCCESS/FAILURE) message is not the job
 * of the method, the eap_authenticator does this.
 * An EAP method may establish a MSK, this is used the complete the
 * authentication. Even if a mutual EAP method is used, the traditional
 * AUTH payloads are required. Only these include the nonces and messages from
 * ike_sa_init and therefore prevent man in the middle attacks.
 */
struct eap_method_t {
	
	/**
	 * Initiate the EAP exchange.
	 *
	 * initiate() is only useable for server implementations, as clients only
	 * reply to server requests.
	 * A eap_payload is created in "out" if result is NEED_MORE.
	 *
	 * @param out		eap_payload to send to the client
	 * @return
	 * 					- NEED_MORE, if an other exchange is required
	 * 					- FAILED, if unable to create eap request payload
	 */
	status_t (*initiate) (eap_method_t *this, eap_payload_t **out);
	
	/**
	 * Process a received EAP message.
	 *
	 * A eap_payload is created in "out" if result is NEED_MORE.
	 *
	 * @param in		eap_payload response received
	 * @param out		created eap_payload to send
	 * @return
	 * 					- NEED_MORE, if an other exchange is required
	 * 					- FAILED, if EAP method failed
	 * 					- SUCCESS, if EAP method succeeded
	 */
	status_t (*process) (eap_method_t *this, eap_payload_t *in,
						 eap_payload_t **out);
	
	/**
	 * Get the EAP type implemented in this method.
	 *
	 * @param vendor	pointer receiving vendor identifier for type, 0 for none
	 * @return			type of the EAP method
	 */
	eap_type_t (*get_type) (eap_method_t *this, u_int32_t *vendor);
	
	/**
	 * Check if this EAP method authenticates the server.
	 *
	 * Some EAP methods provide mutual authentication and 
	 * allow authentication using only EAP, if the peer supports it.
	 *
	 * @return			TRUE if methods provides mutual authentication
	 */
	bool (*is_mutual) (eap_method_t *this);
	
	/**
	 * Get the MSK established by this EAP method.
	 *
	 * Not all EAP methods establish a shared secret.
	 *
	 * @param msk		chunk receiving internal stored MSK
	 * @return
	 *					- SUCCESS, or
	 * 					- FAILED, if MSK not established (yet)
	 */
	status_t (*get_msk) (eap_method_t *this, chunk_t *msk);
	
	/**
	 * Destroys a eap_method_t object.
	 */
	void (*destroy) (eap_method_t *this);
};

/**
 * Constructor definition for a pluggable EAP method.
 *
 * Each EAP module must define a constructor function which will return
 * an initialized object with the methods defined in eap_method_t.
 * Constructors for server and peers are identical, to support both roles
 * of a EAP method, a plugin needs register two constructors in the
 * eap_manager_t.
 *
 * @param server		ID of the server to use for credential lookup
 * @param peer			ID of the peer to use for credential lookup
 * @return				implementation of the eap_method_t interface
 */
typedef eap_method_t *(*eap_constructor_t)(identification_t *server,
										   identification_t *peer);

#endif /* EAP_METHOD_H_ @} */
