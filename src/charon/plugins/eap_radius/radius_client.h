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
 *
 * $Id$
 */

/**
 * @defgroup radius_client radius_client
 * @{ @ingroup eap_radius
 */

#ifndef RADIUS_CLIENT_H_
#define RADIUS_CLIENT_H_

#include "radius_message.h"

typedef struct radius_client_t radius_client_t;

/**
 * RADIUS client functionality.
 *
 * To communicate with a RADIUS server, create a client and send messages over
 * it. All instances share a fixed size pool of sockets. The client reserves
 * a socket during request() and releases it afterwards.
 */
struct radius_client_t {
	
	/**
	 * Send a RADIUS request and wait for the response.
	 *
	 * The client fills in RADIUS Message identifier, NAS-Identifier, 
	 * NAS-Port-Type, builds a Request-Authenticator and calculates the
	 * Message-Authenticator attribute.
	 * The received response gets verified using the Response-Identifier
	 * and the Message-Authenticator attribute.
	 *
	 * @param msg			RADIUS request message to send
	 * @return				response, NULL if timed out/verification failed
	 */
	radius_message_t* (*request)(radius_client_t *this, radius_message_t *msg);
	
	/**
	 * Decrypt the MSK encoded in a messages MS-MPPE-Send/Recv-Key.
	 *
	 * @param response		RADIUS response message containing attributes
	 * @param request		associated RADIUS request message
	 * @return				allocated MSK, empty chunk if none found
	 */
	chunk_t (*decrypt_msk)(radius_client_t *this, radius_message_t *response,
						   radius_message_t *request);
	
	/**
	 * Destroy the client, release the socket.
	 */
	void (*destroy)(radius_client_t *this);
};

/**
 * Create a RADIUS client, acquire a socket.
 *
 * This call might block if the socket pool is empty.
 *
 * @return			radius_client_t object
 */
radius_client_t *radius_client_create();

/**
 * Initialize the socket pool.
 *
 * @return 			TRUE if initialization successful
 */
bool radius_client_init();

/**
 * Cleanup the socket pool.
 */
void radius_client_cleanup();

#endif /** RADIUS_CLIENT_H_ @}*/
