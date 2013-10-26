/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup pt_tls_connection pt_tls_connection
 * @{ @ingroup pt_tls
 */

#ifndef PT_TLS_CONNECTION_H_
#define PT_TLS_CONNECTION_H_

typedef struct pt_tls_connection_t pt_tls_connection_t;

#include <library.h>

#include <tnc/tnccs/tnccs.h>

/**
 * Constructor function for PT-TLS connection
 */
typedef pt_tls_connection_t* (*pt_tls_connection_constructor_t)(tnccs_t *tnccs,
									host_t *host, identification_t *server,
									identification_t *client);

/**
 * Public interface of a PT-TLS connection.
 */
struct pt_tls_connection_t {

	/**
	 * Get IP address of PDP server
	 *
	 * @return		PDP server address
	 */
	host_t* (*get_host)(pt_tls_connection_t *this);

	/**
	 * Start the PT-TLS connection.
	 *
	 * @return		Connection status
	 */
	status_t (*start)(pt_tls_connection_t *this);

	/**
	 * Destroy a pt_tls_connection_t object.
	 */
	void (*destroy)(pt_tls_connection_t *this);
};

#endif /** PT_TLS_CONNECTION_H_ @}*/
