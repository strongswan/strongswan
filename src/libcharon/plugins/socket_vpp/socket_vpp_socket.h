/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup socket_vpp_socket socket_vpp_socket
 * @{ @ingroup socket_vpp
 */

#ifndef SOCKET_VPP_SOCKET_H_
#define SOCKET_VPP_SOCKET_H_

typedef struct socket_vpp_socket_t socket_vpp_socket_t;

#include <network/socket.h>

/**
 * VPP punt socket implementation.
 */
struct socket_vpp_socket_t {

	/**
	 * Implements the socket_t interface.
	 */
	socket_t socket;
};

/**
 * Create a socket_vpp_socket instance.
 */
socket_vpp_socket_t *socket_vpp_socket_create();

#endif /** SOCKET_VPP_SOCKET_H_ @}*/

/*
 * fd.io coding-style-patch-verification: CLANG
 */
