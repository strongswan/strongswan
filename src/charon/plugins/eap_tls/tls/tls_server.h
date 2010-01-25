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
 * @defgroup tls_server tls_server
 * @{ @ingroup tls
 */

#ifndef TLS_SERVER_H_
#define TLS_SERVER_H_

typedef struct tls_server_t tls_server_t;

#include "tls_handshake.h"

/**
 * TLS handshake protocol handler as peer.
 */
struct tls_server_t {

	/**
	 * Implements the TLS handshake protocol handler.
	 */
	tls_handshake_t handshake;
};

/**
 * Create a tls_server instance.
 */
tls_server_t *tls_server_create();

#endif /** TLS_SERVER_H_ @}*/
