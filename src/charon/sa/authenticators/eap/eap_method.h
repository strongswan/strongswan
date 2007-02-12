/**
 * @file eap_method.h
 *
 * @brief Interface eap_method_t.
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
 *
 * @ingroup eap
 */
enum eap_role_t {
	EAP_SERVER,
	EAP_PEER,
};
/**
 * enum names for eap_role_t.
 *
 * @ingroup eap
 */
extern enum_name_t *eap_role_names;

/**
 * EAP types, defines the EAP method implementation
 *
 * @ingroup eap
 */
enum eap_type_t {
	EAP_IDENTITY = 1,
	EAP_NOTIFICATION = 2,
	EAP_NAK = 3,
	EAP_MD5 = 4,
	EAP_ONE_TIME_PASSWORD = 5,
	EAP_TOKEN_CARD = 6,
	EAP_AKA = 23,
};

/**
 * enum names for eap_type_t.
 *
 * @ingroup eap
 */
extern enum_name_t *eap_type_names;

/**
 * EAP code, type of an EAP message
 *
 * @ingroup eap
 */
enum eap_code_t {
	EAP_REQUEST = 1,
	EAP_RESPONSE = 2,
	EAP_SUCCESS = 3,
	EAP_FAILURE = 4,
};

/**
 * enum names for eap_code_t.
 *
 * @ingroup eap
 */
extern enum_name_t *eap_code_names;


/**
 * @brief Interface of an EAP method for server and client side.
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
 *
 * @b Constructors:
 *  - eap_method_create()
 *
 * @ingroup eap
 */
struct eap_method_t {
	
	/**
	 * @brief Initiate the EAP exchange.
	 *
	 * initiate() is only useable for server implementations, as clients only
	 * reply to server requests.
	 * A eap_payload is created in "out" if result is NEED_MORE.
	 *
	 * @param this 		calling object
	 * @param out		eap_payload to send to the client
	 * @return
	 * 					- NEED_MORE, if an other exchange is required
	 * 					- FAILED, if unable to create eap request payload
	 */
	status_t (*initiate) (eap_method_t *this, eap_payload_t **out);
	
	/**
	 * @brief Process a received EAP message.
	 *
	 * A eap_payload is created in "out" if result is NEED_MORE.
	 *
	 * @param this 		calling object
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
	 * @brief Get the EAP type implemented in this method.
	 *
	 * @param this 		calling object
	 * @return			type of the EAP method
	 */
	eap_type_t (*get_type) (eap_method_t *this);
	
	/**
	 * @brief Check if this EAP method authenticates the server.
	 *
	 * Some EAP methods provide mutual authentication and 
	 * allow authentication using only EAP, if the peer supports it.
	 *
	 * @param this 		calling object
	 * @return			TRUE if methods provides mutual authentication
	 */
	bool (*is_mutual) (eap_method_t *this);
	
	/**
	 * @brief Get the MSK established by this EAP method.
	 *
	 * Not all EAP methods establish a shared secret.
	 *
	 * @param this 		calling object
	 * @param msk		chunk receiving internal stored MSK
	 * @return
	 *					- SUCCESS, or
	 * 					- FAILED, if MSK not established (yet)
	 */
	status_t (*get_msk) (eap_method_t *this, chunk_t *msk);
	
	/**
	 * @brief Destroys a eap_method_t object.
	 *
	 * @param this 				calling object
	 */
	void (*destroy) (eap_method_t *this);
};

/**
 * @brief Creates an EAP method for a specific type and role.
 *
 * @param eap_type		EAP type to use
 * @param role			role of the eap_method, server or peer
 * @param server		ID of acting server
 * @param peer			ID of involved peer (client)
 * @return				eap_method_t object
 *
 * @ingroup eap
 */
eap_method_t *eap_method_create(eap_type_t eap_type, eap_role_t role,
								identification_t *server, identification_t *peer);

/**
 * @brief (Re-)Load all EAP modules in the EAP modules directory.
 *
 * For security reasons, the directory and all it's modules must be owned
 * by root and must not be writeable by someone else.
 *
 * @param dir			directory of the EAP modules
 *
 * @ingroup eap
 */
void eap_method_load(char *directory);

/**
 * @brief Unload all loaded EAP modules
 *
 * @ingroup eap
 */
void eap_method_unload();

/**
 * @brief Constructor definition for a pluggable EAP module.
 *
 * Each EAP module must define a constructor function which will return
 * an initialized object with the methods defined in eap_method_t. The
 * constructor must be named eap_create() and it's signature must be equal
 * to that of eap_constructor_t.
 * A module may implement only a single role. If it does not support the role
 * requested, NULL should be returned. Multiple modules are allowed of the
 * same EAP type to support seperate implementations of peer/server.
 *
 * @param role			role the module will play, peer or server
 * @param server		ID of the server to use for credential lookup
 * @param peer			ID of the peer to use for credential lookup
 * @return				implementation of the eap_method_t interface
 *
 * @ingroup eap
 */
typedef eap_method_t *(*eap_constructor_t)(eap_role_t role,
										   identification_t *server,
										   identification_t *peer);

#endif /* EAP_METHOD_H_ */
