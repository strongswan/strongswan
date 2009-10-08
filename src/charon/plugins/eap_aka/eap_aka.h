/*
 * Copyright (C) 2008-2009 Martin Willi
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
 * @defgroup eap_aka_i eap_aka
 * @{ @ingroup eap_aka
 */

#ifndef EAP_AKA_H_
#define EAP_AKA_H_

typedef struct eap_aka_t eap_aka_t;

#include <sa/authenticators/eap/eap_method.h>

/**
 * Implementation of the eap_method_t interface using EAP-AKA.
 *
 * EAP-AKA uses 3rd generation mobile phone standard authentication
 * mechanism for authentication, as defined RFC4187.
 */
struct eap_aka_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * Creates the server implementation of the EAP method EAP-AKA.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_aka_t object
 */
eap_aka_t *eap_aka_create_server(identification_t *server, identification_t *peer);

/**
 * Creates the peer implementation of the EAP method EAP-AKA.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_aka_t object
 */
eap_aka_t *eap_aka_create_peer(identification_t *server, identification_t *peer);

#endif /** EAP_AKA_H_ @}*/
