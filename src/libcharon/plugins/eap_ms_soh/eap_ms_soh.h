/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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
 * @defgroup eap_ms_soh_i eap_ms_soh
 * @{ @ingroup eap_ms_soh
 */

#ifndef EAP_MS_SOH_H_
#define EAP_MS_SOH_H_

typedef struct eap_ms_soh_t eap_ms_soh_t;

#include <sa/eap/eap_method.h>

/**
 * Implementation of Microsoft vendor specific eap_method_t EAP-MS-SOH.
 */
struct eap_ms_soh_t {

	/**
	 * Implements eap_method_t interface.
	 */
	eap_method_t eap_method;
};

/**
 * Creates the EAP method EAP-soh acting as server.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_ms_soh_t object
 */
eap_ms_soh_t *eap_ms_soh_create_server(identification_t *server,
									   identification_t *peer);

/**
 * Creates the EAP method EAP-soh acting as peer.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_ms_soh_t object
 */
eap_ms_soh_t *eap_ms_soh_create_peer(identification_t *server,
									 identification_t *peer);

#endif /** EAP_MS_SOH_H_ @}*/
