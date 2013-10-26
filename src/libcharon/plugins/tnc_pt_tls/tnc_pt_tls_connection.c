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

	/**
	 * IF-TNCCS layer to be transported
	 */
	tnccs_t *tnccs;

};

METHOD(pt_tls_connection_t, get_host, host_t*,
	private_tnc_pt_tls_connection_t *this)
{
	return this->pt_tls_client->get_address(this->pt_tls_client);
}

METHOD(pt_tls_connection_t, start, status_t,
	private_tnc_pt_tls_connection_t *this)
{
	return this->pt_tls_client->start(this->pt_tls_client, this->tnccs);
}

METHOD(pt_tls_connection_t, destroy, void,
	private_tnc_pt_tls_connection_t *this)
{
	tls_t *tls;

	DBG2(DBG_TNC, "destroying PT-TLS connection");
	this->pt_tls_client->destroy(this->pt_tls_client);
	tls = &this->tnccs->tls;
	tls->destroy(tls);
	free(this);
}

/**
 * See header
 */
pt_tls_connection_t *tnc_pt_tls_connection_create(tnccs_t *tnccs, host_t *host,
							identification_t *server, identification_t *client)
{
	private_tnc_pt_tls_connection_t *this;

	INIT(this,
		.public = {
			.get_host = _get_host,
			.start = _start,
			.destroy = _destroy,
		},
		.tnccs = tnccs,
		.pt_tls_client = pt_tls_client_create(host, server, client),
	);

	return &this->public;
}
