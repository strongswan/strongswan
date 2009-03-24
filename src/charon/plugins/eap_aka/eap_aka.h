/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup eap_aka_i eap_aka
 * @{ @ingroup eap_aka
 */

#ifndef EAP_AKA_H_
#define EAP_AKA_H_

typedef struct eap_aka_t eap_aka_t;

#include <sa/authenticators/eap/eap_method.h>

/**  check SEQ values as client for validity, disabled by default */
#ifndef SEQ_CHECK
# define SEQ_CHECK 0
#endif

/**
 * Implementation of the eap_method_t interface using EAP-AKA.
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
 * To enable time based SEQs, define SEQ_CHECK as 1. Default is to accept
 * any SEQ numbers. This allows an attacker to do replay attacks. But since
 * the server has proven his identity via IKE, such an attack is only
 * possible between server and AAA (if any).
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
