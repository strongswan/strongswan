/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "eap_radius_xauth.h"
#include "eap_radius_plugin.h"
#include "eap_radius.h"
#include "eap_radius_forward.h"

#include <daemon.h>
#include <radius_client.h>


typedef struct private_eap_radius_xauth_t private_eap_radius_xauth_t;

/**
 * Private data of an eap_radius_xauth_t object.
 */
struct private_eap_radius_xauth_t {

	/**
	 * Public interface.
	 */
	eap_radius_xauth_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * RADIUS connection
	 */
	radius_client_t *client;
};

METHOD(xauth_method_t, initiate, status_t,
	private_eap_radius_xauth_t *this, cp_payload_t **out)
{
	cp_payload_t *cp;

	cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REQUEST);
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, chunk_empty));
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, chunk_empty));
	*out = cp;
	return NEED_MORE;
}

/**
 * Verify a password using RADIUS User-Name/User-Password attributes
 */
static status_t verify_radius(private_eap_radius_xauth_t *this, chunk_t pass)
{
	radius_message_t *request, *response;
	status_t status = FAILED;

	request = radius_message_create(RMC_ACCESS_REQUEST);
	request->add(request, RAT_USER_NAME, this->peer->get_encoding(this->peer));
	request->add(request, RAT_USER_PASSWORD, pass);

	eap_radius_build_attributes(request);
	eap_radius_forward_from_ike(request);

	response = this->client->request(this->client, request);
	if (response)
	{
		eap_radius_forward_to_ike(response);
		switch (response->get_code(response))
		{
			case RMC_ACCESS_ACCEPT:
				eap_radius_process_attributes(response);
				status = SUCCESS;
				break;
			case RMC_ACCESS_CHALLENGE:
				DBG1(DBG_IKE, "RADIUS Access-Challenge not supported");
				/* FALL */
			case RMC_ACCESS_REJECT:
			default:
				DBG1(DBG_IKE, "RADIUS authentication of '%Y' failed",
					 this->peer);
				break;
		}
		response->destroy(response);
	}
	else
	{
		eap_radius_handle_timeout(NULL);
	}
	request->destroy(request);
	return status;
}

METHOD(xauth_method_t, process, status_t,
	private_eap_radius_xauth_t *this, cp_payload_t *in, cp_payload_t **out)
{
	configuration_attribute_t *attr;
	enumerator_t *enumerator;
	identification_t *id;
	chunk_t user = chunk_empty, pass = chunk_empty;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &attr))
	{
		switch (attr->get_type(attr))
		{
			case XAUTH_USER_NAME:
				user = attr->get_chunk(attr);
				break;
			case XAUTH_USER_PASSWORD:
				pass = attr->get_chunk(attr);
				/* trim password to any null termination. As User-Password
				 * uses null padding, we can't have any null in it, and some
				 * clients actually send null terminated strings (Android). */
				pass.len = strnlen(pass.ptr, pass.len);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!user.ptr || !pass.ptr)
	{
		DBG1(DBG_IKE, "peer did not respond to our XAuth request");
		return FAILED;
	}
	if (user.len)
	{
		id = identification_create_from_data(user);
		if (!id)
		{
			DBG1(DBG_IKE, "failed to parse provided XAuth username");
			return FAILED;
		}
		this->peer->destroy(this->peer);
		this->peer = id;
	}
	return verify_radius(this, pass);
}

METHOD(xauth_method_t, get_identity, identification_t*,
	private_eap_radius_xauth_t *this)
{
	return this->peer;
}

METHOD(xauth_method_t, destroy, void,
	private_eap_radius_xauth_t *this)
{
	DESTROY_IF(this->client);
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	free(this);
}

/*
 * Described in header.
 */
eap_radius_xauth_t *eap_radius_xauth_create_server(identification_t *server,
												   identification_t *peer)
{
	private_eap_radius_xauth_t *this;

	INIT(this,
		.public = {
			.xauth_method = {
				.initiate = _initiate,
				.process = _process,
				.get_identity = _get_identity,
				.destroy = _destroy,
			},
		},
		.server = server->clone(server),
		.peer = peer->clone(peer),
		.client = eap_radius_create_client(),
	);

	if (!this->client)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
