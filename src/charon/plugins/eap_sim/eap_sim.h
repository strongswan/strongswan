/*
 * Copyright (C) 2007-2008 Martin Willi
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
 * @defgroup eap_sim_i eap_sim
 * @{ @ingroup eap_sim
 */

#ifndef EAP_SIM_H_
#define EAP_SIM_H_

typedef struct eap_sim_t eap_sim_t;

#include <sa/authenticators/eap/eap_method.h>

/**
 * Implementation of the eap_method_t interface using EAP-SIM.
 *
 * This EAP-SIM client implementation handles the protocol level of EAP-SIM
 * only, it does not provide triplet calculation/fetching. Other plugins may
 * provide these services using the sim_manager_t of charon.
 */
struct eap_sim_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * Creates the EAP method EAP-SIM acting as server.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_sim_t object
 */
eap_sim_t *eap_sim_create_server(identification_t *server, identification_t *peer);

/**
 * Creates the EAP method EAP-SIM acting as peer.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_sim_t object
 */
eap_sim_t *eap_sim_create_peer(identification_t *server, identification_t *peer);

#endif /* EAP_SIM_H_ @}*/
