/*
 * Copyright (C) 2009 Martin Willi
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

#include "radius_client.h"

#include "eap_radius_plugin.h"
#include "radius_server.h"

#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <utils/host.h>
#include <utils/linked_list.h>
#include <threading/condvar.h>
#include <threading/mutex.h>

typedef struct private_radius_client_t private_radius_client_t;

/**
 * Private data of an radius_client_t object.
 */
struct private_radius_client_t {

	/**
	 * Public radius_client_t interface.
	 */
	radius_client_t public;

	/**
	 * Selected RADIUS server
	 */
	radius_server_t *server;

	/**
	 * RADIUS servers State attribute
	 */
	chunk_t state;

	/**
	 * EAP MSK, from MPPE keys
	 */
	chunk_t msk;
};

/**
 * Save the state attribute to include in further request
 */
static void save_state(private_radius_client_t *this, radius_message_t *msg)
{
	enumerator_t *enumerator;
	int type;
	chunk_t data;

	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_STATE)
		{
			free(this->state.ptr);
			this->state = chunk_clone(data);
			enumerator->destroy(enumerator);
			return;
		}
	}
	enumerator->destroy(enumerator);
	/* no state attribute found, remove state */
	chunk_free(&this->state);
}

METHOD(radius_client_t, request, radius_message_t*,
	private_radius_client_t *this, radius_message_t *req)
{
	char virtual[] = {0x00,0x00,0x00,0x05};
	radius_socket_t *socket;
	radius_message_t *res;

	/* we add the "Virtual" NAS-Port-Type, as we SHOULD include one */
	req->add(req, RAT_NAS_PORT_TYPE, chunk_create(virtual, sizeof(virtual)));
	/* add our NAS-Identifier */
	req->add(req, RAT_NAS_IDENTIFIER,
			 this->server->get_nas_identifier(this->server));
	/* add State attribute, if server sent one */
	if (this->state.ptr)
	{
		req->add(req, RAT_STATE, this->state);
	}
	socket = this->server->get_socket(this->server);
	DBG1(DBG_CFG, "sending RADIUS %N to server '%s'", radius_message_code_names,
		 req->get_code(req), this->server->get_name(this->server));
	res = socket->request(socket, req);
	if (res)
	{
		DBG1(DBG_CFG, "received RADIUS %N from server '%s'",
			 radius_message_code_names, res->get_code(res),
			 this->server->get_name(this->server));
		save_state(this, res);
		if (res->get_code(res) == RMC_ACCESS_ACCEPT)
		{
			chunk_clear(&this->msk);
			this->msk = socket->decrypt_msk(socket, req, res);
		}
		this->server->put_socket(this->server, socket, TRUE);
		return res;
	}
	this->server->put_socket(this->server, socket, FALSE);
	charon->bus->alert(charon->bus, ALERT_RADIUS_NOT_RESPONDING);
	return NULL;
}

METHOD(radius_client_t, get_msk, chunk_t,
	private_radius_client_t *this)
{
	return this->msk;
}

METHOD(radius_client_t, destroy, void,
	private_radius_client_t *this)
{
	this->server->destroy(this->server);
	chunk_clear(&this->msk);
	free(this->state.ptr);
	free(this);
}

/**
 * See header
 */
radius_client_t *radius_client_create()
{
	private_radius_client_t *this;
	enumerator_t *enumerator;
	radius_server_t *server;
	int current, best = -1;

	INIT(this,
		.public = {
			.request = _request,
			.get_msk = _get_msk,
			.destroy = _destroy,
		},
	);

	enumerator = eap_radius_create_server_enumerator();
	while (enumerator->enumerate(enumerator, &server))
	{
		current = server->get_preference(server);
		if (current > best ||
			/* for two with equal preference, 50-50 chance */
			(current == best && random() % 2 == 0))
		{
			DBG2(DBG_CFG, "RADIUS server '%s' is candidate: %d",
				 server->get_name(server), current);
			best = current;
			DESTROY_IF(this->server);
			this->server = server->get_ref(server);
		}
		else
		{
			DBG2(DBG_CFG, "RADIUS server '%s' skipped: %d",
				 server->get_name(server), current);
		}
	}
	enumerator->destroy(enumerator);

	if (!this->server)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}

