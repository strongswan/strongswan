/*
 * Copyright (C) 2012 Tobias Brunner
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

#include "eap_dynamic.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_dynamic_t private_eap_dynamic_t;

/**
 * Private data of an eap_dynamic_t object.
 */
struct private_eap_dynamic_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_dynamic_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * The proxied EAP method
	 */
	eap_method_t *method;
};

METHOD(eap_method_t, initiate, status_t,
	private_eap_dynamic_t *this, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, process, status_t,
	private_eap_dynamic_t *this, eap_payload_t *in, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_dynamic_t *this, u_int32_t *vendor)
{
	if (this->method)
	{
		return this->method->get_type(this->method, vendor);
	}
	*vendor = 0;
	return EAP_DYNAMIC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_dynamic_t *this, chunk_t *msk)
{
	if (this->method)
	{
		return this->method->get_msk(this->method, msk);
	}
	return FAILED;
}

METHOD(eap_method_t, get_identifier, u_int8_t,
	private_eap_dynamic_t *this)
{
	if (this->method)
	{
		return this->method->get_identifier(this->method);
	}
	return 0;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_dynamic_t *this, u_int8_t identifier)
{
	if (this->method)
	{
		this->method->set_identifier(this->method, identifier);
	}
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_dynamic_t *this)
{
	if (this->method)
	{
		return this->method->is_mutual(this->method);
	}
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_dynamic_t *this)
{
	DESTROY_IF(this->method);
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	free(this);
}

/*
 * Defined in header
 */
eap_dynamic_t *eap_dynamic_create(identification_t *server,
								  identification_t *peer)
{
	private_eap_dynamic_t *this;

	INIT(this,
		.public = {
			.interface = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

	return &this->public;
}
