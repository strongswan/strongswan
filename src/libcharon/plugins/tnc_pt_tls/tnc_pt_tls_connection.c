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

#include "tnc_pt_tls_connection.h"

#include <pt_tls_client.h>

typedef struct private_tnc_pt_tls_connection_t private_tnc_pt_tls_connection_t;

/**
 * Private data of an tnc_pt_tls_connection_t object.
 */
struct private_tnc_pt_tls_connection_t {

	/**
	 * Public pt_tls_connection_t interface.
	 */
	pt_tls_connection_t public;

	/**
	 * PT-TLS client instance
	 */
	pt_tls_client_t *pt_tls_client;

};

METHOD(pt_tls_connection_t, destroy, void,
	private_tnc_pt_tls_connection_t *this)
{
	DBG2(DBG_TNC, "destroying PT-TLS connection");
	this->pt_tls_client->destroy(this->pt_tls_client);
	free(this);
}

/**
 * See header
 */
pt_tls_connection_t *tnc_pt_tls_connection_create(tnccs_t *tnccs, host_t *host,
							identification_t *server, identification_t *client)
{
	private_tnc_pt_tls_connection_t *this;

	DBG2(DBG_TNC, "TODO: setup PT-TLS connection to '%Y' at %#H", server, host);

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.pt_tls_client = pt_tls_client_create(host, server, client),
	);

	return &this->public;
}
