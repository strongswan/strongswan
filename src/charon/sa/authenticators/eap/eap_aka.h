/**
 * @file eap_aka.h
 *
 * @brief Interface of eap_aka_t.
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

#ifndef EAP_AKA_H_
#define EAP_AKA_H_

typedef struct eap_aka_t eap_aka_t;
typedef enum aka_subtype_t aka_subtype_t;
typedef enum aka_attribute_t aka_attribute_t;

#include <sa/authenticators/eap/eap_method.h>


/**
 * Subtypes of AKA messages
 */
enum aka_subtype_t {
	AKA_CHALLENGE = 1,
	AKA_AUTHENTICATION_REJECT = 2,
	AKA_SYNCHRONIZATION_FAILURE = 4,
	AKA_IDENTITY = 5,
	AKA_NOTIFICATION = 12,
	AKA_REAUTHENTICATION = 13,
	AKA_CLIENT_ERROR = 14,
};

/**
 * enum names for aka_subtype_t
 */
extern enum_name_t *aka_subtype_names;

/**
 * Attribute types in AKA messages
 */
enum aka_attribute_t {
	/** defines the end of attribute list */
	AT_END = -1,
	AT_RAND = 1,
	AT_AUTN = 2,
	AT_RES = 3,
	AT_AUTS = 4,
	AT_PADDING = 6,
	AT_NONCE_MT = 7,
	AT_PERMANENT_ID_REQ = 10,
	AT_MAC = 11,
	AT_NOTIFICATION = 12,
	AT_ANY_ID_REQ = 13,
	AT_IDENTITY = 14,
	AT_VERSION_LIST = 15,
	AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17,
	AT_COUNTER = 19,
	AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21,
	AT_CLIENT_ERROR_CODE = 22,
	AT_IV = 129,
	AT_ENCR_DATA = 130,
	AT_NEXT_PSEUDONYM = 132,
	AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134,
	AT_RESULT_IND = 135,
};

/**
 * enum names for aka_attribute_t
 */
extern enum_name_t *aka_attribute_names;


/**
 * @brief Implementation of the eap_method_t interface using EAP-AKA.
 *
 * EAP-AKA uses 3rd generation mobile phone standard authentication
 * mechanism for authentication. It is a mutual authentication
 * mechanism which establishs a shared key and therefore supports EAP_ONLY
 * authentication. This implementation follows the standard of the
 * 3GPP2 (S.S0055) and not the one of 3GGP.
 * The shared key used for authentication is from ipsec.secrets. The
 * peers ID is used to query it.
 * The AKA mechanism uses sequence numbers to detect replay attacks. The
 * peer stores the sequence number normally in a USIM and accepts
 * incremental sequence numbers (incremental for lifetime of the USIM). To
 * prevent a complex sequence number management, this implementation uses
 * a sequence number derived from time. It is initialized to the startup
 * time of the daemon. As long as the (UTC) time of the system is not
 * turned back while the daemon is not running, this method is secure.
 *
 * @b Constructors:
 *  - eap_aka_create()
 *  - eap_client_create() using eap_method EAP_AKA
 *
 * @ingroup eap
 */
struct eap_aka_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * @brief Creates the EAP method EAP-AKA.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_aka_t object
 *
 * @ingroup eap
 */
eap_aka_t *eap_create(eap_role_t role,
					  identification_t *server, identification_t *peer);

#endif /* EAP_AKA_H_ */
