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

#include "eap_tls.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_tls_t private_eap_tls_t;

/**
 * Private data of an eap_tls_t object.
 */
struct private_eap_tls_t {

	/**
	 * Public interface.
	 */
	eap_tls_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * Is this method instance acting as server?
	 */
	bool is_server;
};

METHOD(eap_method_t, initiate, status_t,
	private_eap_tls_t *this, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, process, status_t,
	private_eap_tls_t *this, eap_payload_t *in, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_tls_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_TLS;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_tls_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_tls_t *this)
{
	return TRUE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_tls_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/**
 * Generic private constructor
 */
static eap_tls_t *eap_tls_create(identification_t *server,
								 identification_t *peer, bool is_server)
{
	private_eap_tls_t *this;

	INIT(this,
		.public.eap_method = {
			.initiate = _initiate,
			.process = _process,
			.get_type = _get_type,
			.is_mutual = _is_mutual,
			.get_msk = _get_msk,
			.destroy = _destroy,
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.is_server = is_server,
	);
	return &this->public;
}

eap_tls_t *eap_tls_create_server(identification_t *server,
								 identification_t *peer)
{
	return eap_tls_create(server, peer, TRUE);
}

eap_tls_t *eap_tls_create_peer(identification_t *server,
							   identification_t *peer)
{
	return eap_tls_create(server, peer, FALSE);
}
