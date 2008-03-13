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
 
#include "eap_md5.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>

typedef struct private_eap_md5_t private_eap_md5_t;

/**
 * Private data of an eap_md5_t object.
 */
struct private_eap_md5_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	eap_md5_t public;
	
	/**
	 * ID of the server
	 */
	identification_t *server;
	
	/**
	 * ID of the peer
	 */
	identification_t *peer;
	
	/**
	 * challenge sent by the server
	 */
	chunk_t challenge;
	
	/**
	 * EAP message identififier
	 */
	u_int8_t identifier;
};

typedef struct eap_md5_header_t eap_md5_header_t;

/**
 * packed eap MD5 header struct
 */
struct eap_md5_header_t {
	/** EAP code (REQUEST/RESPONSE) */
	u_int8_t code;
	/** unique message identifier */
	u_int8_t identifier;
	/** length of whole message */
	u_int16_t length;
	/** EAP type */
	u_int8_t type;
	/** length of value (challenge) */
	u_int8_t value_size;
	/** actual value */
	u_int8_t value[];
} __attribute__((__packed__));

#define CHALLENGE_LEN 16
#define PAYLOAD_LEN (CHALLENGE_LEN + sizeof(eap_md5_header_t))

/**
 * Hash the challenge string, create response
 */
static status_t hash_challenge(private_eap_md5_t *this, chunk_t *response)
{	
	shared_key_t *shared;
	chunk_t concat;
	hasher_t *hasher;

	shared = charon->credentials->get_shared(charon->credentials, SHARED_EAP,
											 this->server, this->peer);
	if (shared == NULL)
	{
		DBG1(DBG_IKE, "no EAP key found for hosts '%D' - '%D'",
			 this->server, this->peer);
		return NOT_FOUND;
	}
	concat = chunk_cata("ccc", chunk_from_thing(this->identifier),	
						shared->get_key(shared), this->challenge);
	shared->destroy(shared);
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	if (hasher == NULL)
	{
		DBG1(DBG_IKE, "EAP-MD5 failed, MD5 not supported");
		return FAILED;
	}
	hasher->allocate_hash(hasher, concat, response);
	hasher->destroy(hasher);
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.initiate for the peer
 */
static status_t initiate_peer(private_eap_md5_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.initiate for the server
 */
static status_t initiate_server(private_eap_md5_t *this, eap_payload_t **out)
{
	randomizer_t *randomizer;
	status_t status;
	eap_md5_header_t *req;
	
	randomizer = randomizer_create();
	status = randomizer->allocate_pseudo_random_bytes(randomizer, CHALLENGE_LEN,
													  &this->challenge);
	randomizer->destroy(randomizer);
	if (status != SUCCESS)
	{
		return FAILED;
	}
	
	req = alloca(PAYLOAD_LEN);
	req->length = htons(PAYLOAD_LEN);
	req->code = EAP_REQUEST;
	req->identifier = this->identifier;
	req->type = EAP_MD5;
	req->value_size = this->challenge.len;
	memcpy(req->value, this->challenge.ptr, this->challenge.len);
	
	*out = eap_payload_create_data(chunk_create((void*)req, PAYLOAD_LEN));
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for the peer
 */
static status_t process_peer(private_eap_md5_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	chunk_t response;
	chunk_t data;
	eap_md5_header_t *req;
	
	this->identifier = in->get_identifier(in);
	data = in->get_data(in);
	this->challenge = chunk_clone(chunk_skip(data, 6));
	if (data.len < 6 || this->challenge.len < *(data.ptr + 5))
	{
		DBG1(DBG_IKE, "received invalid EAP-MD5 message");
		return FAILED;
	}
	if (hash_challenge(this, &response) != SUCCESS)
	{
		return FAILED;
	}
	req = alloca(PAYLOAD_LEN);
	req->length = htons(PAYLOAD_LEN);
	req->code = EAP_RESPONSE;
	req->identifier = this->identifier;
	req->type = EAP_MD5;
	req->value_size = response.len;
	memcpy(req->value, response.ptr, response.len);
	chunk_free(&response);
	
	*out = eap_payload_create_data(chunk_create((void*)req, PAYLOAD_LEN));
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for the server
 */
static status_t process_server(private_eap_md5_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t response, expected;
	chunk_t data;
	
	if (this->identifier != in->get_identifier(in))
	{
		DBG1(DBG_IKE, "received invalid EAP-MD5 message");
		return FAILED;
	}
	if (hash_challenge(this, &expected) != SUCCESS)
	{
		return FAILED;
	}
	data = in->get_data(in);
	response = chunk_skip(data, 6);
	
	if (response.len < expected.len ||
		!memeq(response.ptr, expected.ptr, expected.len))
	{
		chunk_free(&expected);
		DBG1(DBG_IKE, "EAP-MD5 verification failed");
		return FAILED;
	}
	chunk_free(&expected);
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_md5_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_MD5;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_md5_t *this, chunk_t *msk)
{
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_md5_t *this)
{
	return FALSE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_md5_t *this)
{
	chunk_free(&this->challenge);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_md5_t *eap_md5_create_generic(identification_t *server,
												 identification_t *peer)
{
	private_eap_md5_t *this = malloc_thing(private_eap_md5_t);
	
	this->public.eap_method_interface.initiate = NULL;
	this->public.eap_method_interface.process = NULL;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;
	
	/* private data */
	this->peer = peer;
	this->server = server;
	this->challenge = chunk_empty;
	this->identifier = random();
	
	return this;
}

/*
 * see header
 */
eap_md5_t *eap_md5_create_server(identification_t *server, identification_t *peer)
{
	private_eap_md5_t *this = eap_md5_create_generic(server, peer);
	
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_server;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_server;

	return &this->public;
}

/*
 * see header
 */
eap_md5_t *eap_md5_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_md5_t *this = eap_md5_create_generic(server, peer);
	
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_peer;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_peer;

	return &this->public;
}

