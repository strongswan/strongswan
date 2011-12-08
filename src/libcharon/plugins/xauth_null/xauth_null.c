/*
 * Copyright (C) 2007-2008 Martin Willi
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

#include "xauth_null.h"

#include <daemon.h>
#include <library.h>

typedef struct private_xauth_null_t private_xauth_null_t;

/**
 * Private data of an xauth_null_t object.
 */
struct private_xauth_null_t {

	/**
	 * Public authenticator_t interface.
	 */
	xauth_null_t public;

	/**
	 * ID of the peer
	 */
	identification_t *peer;
};

METHOD(xauth_method_t, process_peer, status_t,
	private_xauth_null_t *this, cp_payload_t *in, cp_payload_t **out)
{
	chunk_t user_name = chunk_from_chars('j', 'o', 's', 't');
	chunk_t user_pass = chunk_from_chars('j', 'o', 's', 't');
	cp_payload_t *cp;

	/* TODO-IKEv1: Fetch the user/pass from an authenticator */
	cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REPLY);
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, user_name));
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, user_pass));
	*out = cp;
	return NEED_MORE;
}

METHOD(xauth_method_t, initiate_peer, status_t,
	private_xauth_null_t *this, cp_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

METHOD(xauth_method_t, process_server, status_t,
	private_xauth_null_t *this, cp_payload_t *in, cp_payload_t **out)
{
	return SUCCESS;
}

METHOD(xauth_method_t, initiate_server, status_t,
	private_xauth_null_t *this, cp_payload_t **out)
{
	return NEED_MORE;
}

METHOD(xauth_method_t, destroy, void,
	private_xauth_null_t *this)
{
	this->peer->destroy(this->peer);
	free(this);
}

/*
 * Described in header.
 */
xauth_null_t *xauth_null_create_peer(identification_t *server,
									 identification_t *peer)
{
	private_xauth_null_t *this;

	INIT(this,
		.public =  {
			.xauth_method = {
				.initiate = _initiate_peer,
				.process = _process_peer,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
	);

	return &this->public;
}

/*
 * Described in header.
 */
xauth_null_t *xauth_null_create_server(identification_t *server,
										   identification_t *peer)
{
	private_xauth_null_t *this;

	INIT(this,
		.public = {
			.xauth_method = {
				.initiate = _initiate_server,
				.process = _process_server,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
	);

	return &this->public;
}
