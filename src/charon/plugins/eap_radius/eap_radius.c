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

#include "eap_radius.h"

#include "radius_message.h"
#include "radius_client.h"

#include <daemon.h>

typedef struct private_eap_radius_t private_eap_radius_t;

/**
 * Private data of an eap_radius_t object.
 */
struct private_eap_radius_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_radius_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP method type we are proxying
	 */
	eap_type_t type;

	/**
	 * EAP vendor, if any
	 */
	u_int32_t vendor;

	/**
	 * EAP MSK, if method established one
	 */
	chunk_t msk;

	/**
	 * RADIUS client instance
	 */
	radius_client_t *client;

	/**
	 * TRUE to use EAP-Start, FALSE to send EAP-Identity Response directly
	 */
	bool eap_start;

	/**
	 * Prefix to prepend to EAP identity
	 */
	char *id_prefix;
};

/**
 * Add EAP-Identity to RADIUS message
 */
static void add_eap_identity(private_eap_radius_t *this,
							 radius_message_t *request)
{
	struct {
		/** EAP code (REQUEST/RESPONSE) */
		u_int8_t code;
		/** unique message identifier */
		u_int8_t identifier;
		/** length of whole message */
		u_int16_t length;
		/** EAP type */
		u_int8_t type;
		/** identity data */
		u_int8_t data[];
	} __attribute__((__packed__)) *hdr;
	chunk_t id, prefix;
	size_t len;

	id = this->peer->get_encoding(this->peer);
	prefix = chunk_create(this->id_prefix, strlen(this->id_prefix));
	len = sizeof(*hdr) + prefix.len + id.len;

	hdr = alloca(len);
	hdr->code = EAP_RESPONSE;
	hdr->identifier = 0;
	hdr->length = htons(len);
	hdr->type = EAP_IDENTITY;
	memcpy(hdr->data, prefix.ptr, prefix.len);
	memcpy(hdr->data + prefix.len, id.ptr, id.len);

	request->add(request, RAT_EAP_MESSAGE, chunk_create((u_char*)hdr, len));
}

/**
 * Copy EAP-Message attribute from RADIUS message to an new EAP payload
 */
static bool radius2ike(private_eap_radius_t *this,
					   radius_message_t *msg, eap_payload_t **out)
{
	enumerator_t *enumerator;
	eap_payload_t *payload;
	chunk_t data, message = chunk_empty;
	int type;

	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_EAP_MESSAGE && data.len)
		{
			message = chunk_cat("mc", message, data);
		}
	}
	enumerator->destroy(enumerator);
	if (message.len)
	{
		*out = payload = eap_payload_create_data(message);
		free(message.ptr);
		/* apply EAP method selected by RADIUS server */
		this->type = payload->get_type(payload, &this->vendor);
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of eap_method_t.initiate
 */
static status_t initiate(private_eap_radius_t *this, eap_payload_t **out)
{
	radius_message_t *request, *response;
	status_t status = FAILED;
	chunk_t username;

	request = radius_message_create_request();
	username = chunk_create(this->id_prefix, strlen(this->id_prefix));
	username = chunk_cata("cc", username, this->peer->get_encoding(this->peer));
	request->add(request, RAT_USER_NAME, username);

	if (this->eap_start)
	{
		request->add(request, RAT_EAP_MESSAGE, chunk_empty);
	}
	else
	{
		add_eap_identity(this, request);
	}

	response = this->client->request(this->client, request);
	if (response)
	{
		if (radius2ike(this, response, out))
		{
			status = NEED_MORE;
		}
		response->destroy(response);
	}
	request->destroy(request);
	return status;
}

/**
 * Implementation of eap_method_t.process
 */
static status_t process(private_eap_radius_t *this,
						eap_payload_t *in, eap_payload_t **out)
{
	radius_message_t *request, *response;
	status_t status = FAILED;
	chunk_t data;

	request = radius_message_create_request();
	request->add(request, RAT_USER_NAME, this->peer->get_encoding(this->peer));
	data = in->get_data(in);
	/* fragment data suitable for RADIUS (not more than 253 bytes) */
	while (data.len > 253)
	{
		request->add(request, RAT_EAP_MESSAGE, chunk_create(data.ptr, 253));
		data = chunk_skip(data, 253);
	}
	request->add(request, RAT_EAP_MESSAGE, data);

	response = this->client->request(this->client, request);
	if (response)
	{
		switch (response->get_code(response))
		{
			case RMC_ACCESS_CHALLENGE:
				if (radius2ike(this, response, out))
				{
					status = NEED_MORE;
					break;
				}
				status = FAILED;
				break;
			case RMC_ACCESS_ACCEPT:
				this->msk = this->client->decrypt_msk(this->client,
													  response, request);
				status = SUCCESS;
				break;
			case RMC_ACCESS_REJECT:
			default:
				DBG1(DBG_CFG, "received %N from RADIUS server",
					 radius_message_code_names, response->get_code(response));
				status = FAILED;
				break;
		}
		response->destroy(response);
	}
	request->destroy(request);
	return status;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_radius_t *this, u_int32_t *vendor)
{
	*vendor = this->vendor;
	return this->type;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_radius_t *this, chunk_t *msk)
{
	if (this->msk.ptr)
	{
		*msk = this->msk;
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_radius_t *this)
{
	switch (this->type)
	{
		case EAP_AKA:
		case EAP_SIM:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_radius_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	this->client->destroy(this->client);
	chunk_clear(&this->msk);
	free(this);
}

/**
 * Generic constructor
 */
eap_radius_t *eap_radius_create(identification_t *server, identification_t *peer)
{
	private_eap_radius_t *this = malloc_thing(private_eap_radius_t);

	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;

	this->client = radius_client_create();
	if (!this->client)
	{
		free(this);
		return NULL;
	}
	this->peer = peer->clone(peer);
	this->server = server->clone(server);
	/* initially EAP_RADIUS, but is set to the method selected by RADIUS */
	this->type = EAP_RADIUS;
	this->vendor = 0;
	this->msk = chunk_empty;
	this->eap_start = lib->settings->get_bool(lib->settings,
								"charon.plugins.eap-radius.eap_start", FALSE);
	this->id_prefix = lib->settings->get_str(lib->settings,
								"charon.plugins.eap-radius.id_prefix", "");
	return &this->public;
}

