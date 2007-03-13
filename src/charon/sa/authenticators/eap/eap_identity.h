/**
 * @file eap_identity.h
 *
 * @brief Interface of eap_identity_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef EAP_IDENTITY_H_
#define EAP_IDENTITY_H_

typedef struct eap_identity_t eap_identity_t;

#include <sa/authenticators/eap/eap_method.h>

/**
 * @brief Implementation of the eap_method_t interface using EAP Identity.
 *
 * @b Constructors:
 *  - eap_identity_create()
 *  - eap_client_create() using eap_method EAP_IDENTITY
 *
 * @ingroup eap
 */
struct eap_identity_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * @brief Creates the EAP method EAP Identity.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_identity_t object
 *
 * @ingroup eap
 */
eap_identity_t *eap_create(eap_role_t role,
					  	   identification_t *server, identification_t *peer);

#endif /* EAP_IDENTITY_H_ */
