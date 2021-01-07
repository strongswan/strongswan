/*
 * Copyright (C) 2010-2013 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
	status_t (*receive)(socket_manager_t *this, packet_t **packet);

	/**
	 * Send a packet using the registered socket.
	 *
	 * @param packet		packet to send out
	 * @return
	 *						- SUCCESS when packet successfully sent
	 *						- FAILED when unable to send
	 */
	status_t (*send)(socket_manager_t *this, packet_t *packet);

	/**
	 * Get the port the registered socket is listening on.
	 *
	 * @param nat_t			TRUE to get the port used to float in case of NAT-T
	 * @return				the port, or 0, if no socket is registered
	 */
	uint16_t (*get_port)(socket_manager_t *this, socket_family_t family, bool nat_t);

	/**
	 * Get the address families the registered socket is listening on.
	 *
	 * @return				address families
	 */
	socket_family_t (*supported_families)(socket_manager_t *this);

	/**
	 * Register a socket constructor.
	 *
	 * @param create		constructor for the socket
	 */
	void (*add_socket)(socket_manager_t *this, socket_constructor_t create);

	/**
	 * Unregister a registered socket constructor.
	 *
	 * @param create		constructor for the socket
	 */
	void (*remove_socket)(socket_manager_t *this, socket_constructor_t create);

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
