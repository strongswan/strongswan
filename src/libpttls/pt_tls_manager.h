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
 * @defgroup pt_tls_manager pt_tls_manager
 * @{ @ingroup pt_tls
 */

#ifndef PT_TLS_MANAGER_H_
#define PT_TLS_MANAGER_H_

typedef struct pt_tls_manager_t pt_tls_manager_t;

#include "pt_tls_connection.h"

/**
 * The PT-TLS manager handles multiple PT-TLS connections.
 */
struct pt_tls_manager_t {

	/**
	 * Create a PT-TLS connection instance.
	 *
	 * @param tnccs			IF-TNCCS connection to be transported
	 * @param host			IP address of PDP server
	 * @param server		Hostname of PDP server
	 * @param client		Access Requestor Identity
	 */
	pt_tls_connection_t* (*create_connection)(pt_tls_manager_t *this,
											  tnccs_t *tnccs, host_t *host,
										      identification_t *server,
											  identification_t *client);

	/**
	 * Register a PT-TLS connection with the manager.
	 *
	 * @param connection	PT-TLS connection to register
	 */
	void (*add_connection)(pt_tls_manager_t *this,
						   pt_tls_connection_t *connection);

	/**
	 * Unregister a previously registered connection from the manager.
	 *
	 * @param connection	PT-TLS connection to unregister
	 */
	void (*remove_connection)(pt_tls_manager_t *this,
							  pt_tls_connection_t *connection);

	/**
	 * Enumerate over all registered PT-TLS connections
	 *
	 * @return				PT-TLS connection enumerator
	 */
	enumerator_t* (*create_connection_enumerator)(pt_tls_manager_t *this);

	/**
	 * Destroy a manager instance.
	 */
	void (*destroy)(pt_tls_manager_t *this);
};

/**
 * Create a PT-TLS manager to handle multiple PT-TLS connections.
 *
 * @return			pt_tls_manager_t object
 */
pt_tls_manager_t *pt_tls_manager_create();

#endif /** PT_TLS_MANAGER_H_ @}*/
