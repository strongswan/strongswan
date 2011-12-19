/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup eap_radius_i eap_radius
 * @{ @ingroup eap_radius
 */

#ifndef EAP_RADIUS_H_
#define EAP_RADIUS_H_

typedef struct eap_radius_t eap_radius_t;

#include <sa/eap/eap_method.h>

/**
 * Implementation of the eap_method_t interface using a RADIUS server.
 */
struct eap_radius_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method;
};

/**
 * Create a EAP RADIUS proxy.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_radius_t object
 */
eap_radius_t *eap_radius_create(identification_t *server, identification_t *peer);

#endif /** EAP_RADIUS_H_ @}*/
