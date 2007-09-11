/**
 * @file psk_authenticator.c
 *
 * @brief Implementation of psk_authenticator_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <string.h>

#include "psk_authenticator.h"

#include <daemon.h>

/**
 * Key pad for the AUTH method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
#define IKEV2_KEY_PAD "Key Pad for IKEv2"
#define IKEV2_KEY_PAD_LENGTH 17


typedef struct private_psk_authenticator_t private_psk_authenticator_t;

/**
 * Private data of an psk_authenticator_t object.
 */
struct private_psk_authenticator_t {

	/**
	 * Public authenticator_t interface.
	 */
	psk_authenticator_t public;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;
};

/**
 * Builds the octets to be signed as described in section 2.15 of RFC 4306
 */
chunk_t build_tbs_octets(chunk_t ike_sa_init, chunk_t nonce,
						 identification_t *id, prf_t *prf)
{
	u_int8_t id_header_buf[] = {0x00, 0x00, 0x00, 0x00};
	chunk_t id_header = chunk_from_buf(id_header_buf);
	chunk_t id_with_header, id_prfd, id_encoding;
	
	id_header_buf[0] = id->get_type(id);
	id_encoding = id->get_encoding(id);
	
	id_with_header = chunk_cat("cc", id_header, id_encoding);
	prf->allocate_bytes(prf, id_with_header, &id_prfd);
	chunk_free(&id_with_header);
	
	return chunk_cat("ccm", ike_sa_init, nonce, id_prfd);
}

/**
 * Creates the AUTH data using auth method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
chunk_t build_shared_key_signature(chunk_t ike_sa_init, chunk_t nonce,
								   chunk_t secret, identification_t *id,
								   chunk_t skp, prf_t *prf)
{
	chunk_t key_pad, key, auth_data, octets;
	
	prf->set_key(prf, skp);
	octets = build_tbs_octets(ike_sa_init, nonce, id, prf);
	/* AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>) */
	key_pad.ptr = IKEV2_KEY_PAD;
	key_pad.len = IKEV2_KEY_PAD_LENGTH;
	prf->set_key(prf, secret);
	prf->allocate_bytes(prf, key_pad, &key);
	prf->set_key(prf, key);
	prf->allocate_bytes(prf, octets, &auth_data);
	DBG3(DBG_IKE, "octets = message + nonce + prf(Sk_px, IDx') %B", &octets);
	DBG3(DBG_IKE, "secret %B", &secret);
	DBG3(DBG_IKE, "keypad %B", &key_pad);
	DBG3(DBG_IKE, "prf(secret, keypad) %B", &key);
	DBG3(DBG_IKE, "AUTH = prf(prf(secret, keypad), octets) %B", &auth_data);
	chunk_free(&octets);
	chunk_free(&key);
	
	return auth_data;
}

/**
 * Implementation of authenticator_t.verify.
 */
static status_t verify(private_psk_authenticator_t *this, chunk_t ike_sa_init,
 				chunk_t my_nonce, auth_payload_t *auth_payload)
{
	status_t status;
	chunk_t auth_data, recv_auth_data, shared_key;
	identification_t *my_id, *other_id;
	
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	status = charon->credentials->get_shared_key(charon->credentials, my_id,
												 other_id, &shared_key);
	if (status != SUCCESS)
	{
		DBG1(DBG_IKE, "no shared key found for '%D' - '%D'",  my_id, other_id);
		return status;
	}
	
	auth_data = build_shared_key_signature(ike_sa_init, my_nonce, shared_key,
						other_id, this->ike_sa->get_skp_verify(this->ike_sa),
						this->ike_sa->get_prf(this->ike_sa));
	chunk_free_randomized(&shared_key);
	
	recv_auth_data = auth_payload->get_data(auth_payload);
	if (auth_data.len != recv_auth_data.len ||
		!memeq(auth_data.ptr, recv_auth_data.ptr, auth_data.len))
	{
		DBG1(DBG_IKE, "PSK MAC verification failed");
		chunk_free(&auth_data);
		return FAILED;
	}
	chunk_free(&auth_data);
	
	DBG1(DBG_IKE, "authentication of '%D' with %N successful",
		 other_id, auth_method_names, AUTH_PSK);
	return SUCCESS;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_psk_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	chunk_t shared_key;
	chunk_t auth_data;
	status_t status;
	identification_t *my_id, *other_id;
	
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_method_names, AUTH_PSK);
	status = charon->credentials->get_shared_key(charon->credentials, my_id,
												 other_id, &shared_key);
	if (status != SUCCESS)
	{
		DBG1(DBG_IKE, "no shared key found for '%D' - '%D'", my_id, other_id);
		return status;
	}
			
	auth_data = build_shared_key_signature(ike_sa_init, other_nonce, shared_key,
							my_id, this->ike_sa->get_skp_build(this->ike_sa),
							this->ike_sa->get_prf(this->ike_sa));
	DBG2(DBG_IKE, "successfully created shared key MAC");
	chunk_free_randomized(&shared_key);
	*auth_payload = auth_payload_create();
	(*auth_payload)->set_auth_method(*auth_payload, AUTH_PSK);
	(*auth_payload)->set_data(*auth_payload, auth_data);
	
	chunk_free(&auth_data);
	return SUCCESS;
}

/**
 * Implementation of authenticator_t.destroy.
 */
static void destroy(private_psk_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
psk_authenticator_t *psk_authenticator_create(ike_sa_t *ike_sa)
{
	private_psk_authenticator_t *this = malloc_thing(private_psk_authenticator_t);
	
	/* public functions */
	this->public.authenticator_interface.verify = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t*))verify;
	this->public.authenticator_interface.build = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t**))build;
	this->public.authenticator_interface.destroy = (void(*)(authenticator_t*))destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	
	return &this->public;
}
