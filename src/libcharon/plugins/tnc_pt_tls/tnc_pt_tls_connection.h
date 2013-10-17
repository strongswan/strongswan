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
 * @defgroup tnc_pt_tls_connection tnc_pt_tls_connection
 * @{ @ingroup pt_tls
 */

#ifndef TNC_PT_TLS_CONNECTION_H_
#define TNC_PT_TLS_CONNECTION_H_


#include <library.h>

#include <pt_tls_connection.h>

/**
 * Create a PT-TLS connection instance.
 *
 * @param tnccs			IF-TNCCS connection to be transported
 * @param host			IP address of PDP server
 * @param server		Hostname of PDP server
 * @param client		Access Requestor Identity
 */
pt_tls_connection_t* tnc_pt_tls_connection_create(tnccs_t *tnccs, host_t *host,
							identification_t *server, identification_t *client);

#endif /** TNC_PT_TLS_CONNECTION_H_ @}*/
