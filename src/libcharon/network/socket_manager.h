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
 * @defgroup socket_manager socket_manager
 * @{ @ingroup network
 */

#ifndef SOCKET_MANAGER_H_
#define SOCKET_MANAGER_H_

#include <network/socket.h>

typedef struct socket_manager_t socket_manager_t;

/**
 * Handle pluggable socket implementations and send/receive packets through it.
 */
struct socket_manager_t {

	/**
	 * Receive a packet using the registered socket.
	 *
	 * @param packet		allocated packet that has been received
	 * @return
	 *						- SUCCESS when packet successfully received
	 *						- FAILED when unable to receive
	 */
	status_t (*receive) (socket_manager_t *this, packet_t **packet);

	/**
	 * Send a packet using the registered socket.
	 *
	 * @param packet		packet to send out
	 * @return
	 *						- SUCCESS when packet successfully sent
	 *						- FAILED when unable to send
	 */
	status_t (*send) (socket_manager_t *this, packet_t *packet);

	/**
	 * Register a socket implementation.
	 */
	void (*add_socket)(socket_manager_t *this, socket_t *socket);

	/**
	 * Unregister a registered socket implementation.
	 */
	void (*remove_socket)(socket_manager_t *this, socket_t *socket);

	/**
	 * Destroy a socket_manager_t.
	 */
	void (*destroy)(socket_manager_t *this);
};

/**
 * Create a socket_manager instance.
 */
socket_manager_t *socket_manager_create();

#endif /** SOCKET_MANAGER_H_ @}*/
