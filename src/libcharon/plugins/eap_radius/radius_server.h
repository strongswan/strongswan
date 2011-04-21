/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup radius_server radius_server
 * @{ @ingroup eap_radius
 */

#ifndef RADIUS_SERVER_H_
#define RADIUS_SERVER_H_

typedef struct radius_server_t radius_server_t;

#include "radius_socket.h"

/**
 * RADIUS server configuration.
 */
struct radius_server_t {

	/**
	 * Get a RADIUS socket from the pool to communicate with this server.
	 *
	 * @return			RADIUS socket
	 */
	radius_socket_t* (*get_socket)(radius_server_t *this);

	/**
	 * Release a socket to the pool after use.
	 *
	 * @param skt		RADIUS socket to release
	 * @param result	result of the socket use, TRUE for success
	 */
	void (*put_socket)(radius_server_t *this, radius_socket_t *skt, bool result);

	/**
	 * Get the NAS-Identifier to use with this server.
	 *
	 * @return			NAS-Identifier, internal data
	 */
	chunk_t (*get_nas_identifier)(radius_server_t *this);

	/**
	 * Get the preference of this server.
	 *
	 * Based on the available sockets and the server reachability a preference
	 * value is calculated: better servers return a higher value.
	 */
	int (*get_preference)(radius_server_t *this);

	/**
	 * Get the name of the RADIUS server.
	 *
	 * @return			server name
	 */
	char* (*get_name)(radius_server_t *this);

	/**
	 * Increase reference count of this server.
	 *
	 * @return			this
	 */
	radius_server_t* (*get_ref)(radius_server_t *this);

	/**
	 * Destroy a radius_server_t.
	 */
	void (*destroy)(radius_server_t *this);
};

/**
 * Create a radius_server instance.
 *
 * @param name				server name
 * @param address			server address
 * @param port				server port
 * @param nas_identifier	NAS-Identifier to use with this server
 * @param secret			secret to use with this server
 * @param sockets			number of sockets to create in pool
 * @param preference		preference boost for this server
 */
radius_server_t *radius_server_create(char *name, char *address, u_int16_t port,
			char *nas_identifier, char *secret, int sockets, int preference);

#endif /** RADIUS_SERVER_H_ @}*/
