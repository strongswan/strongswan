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
 * @defgroup socket_raw_socket socket_raw_socket
 * @{ @ingroup socket_raw
 */

#ifndef SOCKET_RAW_SOCKET_H_
#define SOCKET_RAW_SOCKET_H_

typedef struct socket_raw_socket_t socket_raw_socket_t;

#include <network/socket.h>

/**
 * Raw socket, binds to port 500/4500 using any IPv4/IPv6 address.
 *
 * This imeplementation uses raw sockets to allow binding of other daemons
 * (pluto) to UDP/500/4500. An installed "Linux socket filter" filters out
 * all non-IKEv2 traffic and handles just IKEv2 messages. An other daemon
 * must handle all traffic separately, e.g. ignore IKEv2 traffic, since charon
 * handles that.
 */
struct socket_raw_socket_t {

	/**
	 * Implements the socket_t interface.
	 */
	socket_t socket;

	/**
	 * Destroy a socket_raw_socket_t.
	 */
	void (*destroy)(socket_raw_socket_t *this);
};

/**
 * Create a socket_raw_socket instance.
 */
socket_raw_socket_t *socket_raw_socket_create();

#endif /** SOCKET_RAW_SOCKET_H_ @}*/
