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
 */

/**
 * @defgroup xauth_null_i xauth_null
 * @{ @ingroup xauth_null
 */

#ifndef XAUTH_NULL_H_
#define XAUTH_NULL_H_

typedef struct xauth_null_t xauth_null_t;

#include <sa/authenticators/xauth/xauth_method.h>

/**
 * Implementation of the xauth_method_t providing no actual identity verification.
 */
struct xauth_null_t {

	/**
	 * Implemented xauth_method_t interface.
	 */
	xauth_method_t xauth_method;
};

/**
 * Creates the XAuth method XAuth NULL, acting as server.
 *
 * @param server	ID of the XAuth server
 * @param peer		ID of the XAuth client
 * @return			xauth_null_t object
 */
xauth_null_t *xauth_null_create_server(identification_t *server,
										   identification_t *peer);

/**
 * Creates the XAuth method XAuth NULL, acting as peer.
 *
 * @param server	ID of the XAuth server
 * @param peer		ID of the XAuth client
 * @return			xauth_null_t object
 */
xauth_null_t *xauth_null_create_peer(identification_t *server,
										 identification_t *peer);

#endif /** XAUTH_NULL_H_ @}*/
