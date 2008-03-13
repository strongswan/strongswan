/*
 * Copyright (C) 2007 Martin Willi
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
 *
 * $Id$
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
};

/**
 * Implementation of eap_method_t.process for the peer
 */
static status_t process(private_eap_identity_t *this,
						eap_payload_t *in, eap_payload_t **out)
{
	chunk_t id, hdr;
	
	hdr = chunk_alloca(5);
	id = this->peer->get_encoding(this->peer);
	
	*(hdr.ptr + 0) = EAP_RESPONSE;
	*(hdr.ptr + 1) = in->get_identifier(in);
	*(u_int16_t*)(hdr.ptr + 2) = htons(hdr.len + id.len);
	*(hdr.ptr + 4) = EAP_IDENTITY;
	
	*out = eap_payload_create_data(chunk_cata("cc", hdr, id));
	return SUCCESS;
	
}

/**
 * Implementation of eap_method_t.initiate for the peer
 */
static status_t initiate(private_eap_identity_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
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
	free(this);
}

/*
 * Described in header.
 */
eap_identity_t *eap_identity_create_peer(identification_t *server,
										 identification_t *peer)
{
	private_eap_identity_t *this = malloc_thing(private_eap_identity_t);
	
	/* public functions */
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;
	
	/* private data */
	this->peer = peer;
	
	return &this->public;
}

