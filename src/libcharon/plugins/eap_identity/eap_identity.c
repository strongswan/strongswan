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

#include "eap_identity.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_identity_t private_eap_identity_t;

/**
 * Private data of an eap_identity_t object.
 */
struct private_eap_identity_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_identity_t public;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * received identity chunk
	 */
	chunk_t identity;
};

typedef struct eap_identity_header_t eap_identity_header_t;

/**
 * packed EAP Identity header struct
 */
struct eap_identity_header_t {
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
} __attribute__((__packed__));

/**
 * Implementation of eap_method_t.process for the peer
 */
static status_t process_peer(private_eap_identity_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	chunk_t id;
	eap_identity_header_t *hdr;
	size_t len;

	id = this->peer->get_encoding(this->peer);
	len = sizeof(eap_identity_header_t) + id.len;

	hdr = alloca(len);
	hdr->code = EAP_RESPONSE;
	hdr->identifier = in->get_identifier(in);
	hdr->length = htons(len);
	hdr->type = EAP_IDENTITY;
	memcpy(hdr->data, id.ptr, id.len);

	*out = eap_payload_create_data(chunk_create((u_char*)hdr, len));
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.initiate for the peer
 */
static status_t initiate_peer(private_eap_identity_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.process for the server
 */
static status_t process_server(private_eap_identity_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t data;

	data = chunk_skip(in->get_data(in), 5);
	if (data.len)
	{
		this->identity = chunk_clone(data);
	}
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.initiate for the server
 */
static status_t initiate_server(private_eap_identity_t *this, eap_payload_t **out)
{
	eap_identity_header_t hdr;

	hdr.code = EAP_REQUEST;
	hdr.identifier = 0;
	hdr.length = htons(sizeof(eap_identity_header_t));
	hdr.type = EAP_IDENTITY;

	*out = eap_payload_create_data(chunk_create((u_char*)&hdr,
												sizeof(eap_identity_header_t)));
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_identity_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_IDENTITY;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_identity_t *this, chunk_t *msk)
{
	if (this->identity.ptr)
	{
		*msk = this->identity;
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_identity_t *this)
{
	return FALSE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_identity_t *this)
{
	this->peer->destroy(this->peer);
	free(this->identity.ptr);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_identity_t *eap_identity_create(identification_t *server,
												   identification_t *peer)
{
	private_eap_identity_t *this = malloc_thing(private_eap_identity_t);

	this->public.eap_method_interface.initiate = NULL;
	this->public.eap_method_interface.process = NULL;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;

	this->peer = peer->clone(peer);
	this->identity = chunk_empty;

	return this;
}

/*
 * Described in header.
 */
eap_identity_t *eap_identity_create_peer(identification_t *server,
										 identification_t *peer)
{
	private_eap_identity_t *this = eap_identity_create(server, peer);

	/* public functions */
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_peer;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_peer;

	return &this->public;
}

/*
 * Described in header.
 */
eap_identity_t *eap_identity_create_server(identification_t *server,
										   identification_t *peer)
{
	private_eap_identity_t *this = eap_identity_create(server, peer);

	/* public functions */
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_server;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_server;

	return &this->public;
}

