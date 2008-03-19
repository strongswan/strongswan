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
 *
 * $Id$
 */

#include <string.h>

#include "rsa_authenticator.h"

#include <daemon.h>
#include <credentials/auth_info.h>


typedef struct private_rsa_authenticator_t private_rsa_authenticator_t;

/**
 * Private data of an rsa_authenticator_t object.
 */
struct private_rsa_authenticator_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	rsa_authenticator_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;
};

/**
 * Function implemented in psk_authenticator.c
 */
extern chunk_t build_tbs_octets(chunk_t ike_sa_init, chunk_t nonce,
								identification_t *id, prf_t *prf);

/**
 * Implementation of authenticator_t.verify.
 */
static status_t verify(private_rsa_authenticator_t *this, chunk_t ike_sa_init,
 					   chunk_t my_nonce, auth_payload_t *auth_payload)
{
	public_key_t *public;
	chunk_t auth_data, octets;
	identification_t *other_id;
	prf_t *prf;
	auth_info_t *auth;
	status_t status = FAILED;
	
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	
	if (auth_payload->get_auth_method(auth_payload) != AUTH_RSA)
	{
		return INVALID_ARG;
	}
	auth_data = auth_payload->get_data(auth_payload);
	prf = this->ike_sa->get_prf(this->ike_sa);
	prf->set_key(prf, this->ike_sa->get_skp_verify(this->ike_sa));
	octets = build_tbs_octets(ike_sa_init, my_nonce, other_id, prf);
	
	auth = this->ike_sa->get_other_auth(this->ike_sa);
	public = charon->credentials->get_public(charon->credentials, KEY_RSA,
											 other_id, auth);
	if (public)
	{
		/* We are currently fixed to SHA1 hashes.
		 * TODO: allow other hash algorithms and note it in "auth" */
		if (public->verify(public, SIGN_RSA_EMSA_PKCS1_SHA1, octets, auth_data))
		{
			DBG1(DBG_IKE, "authentication of '%D' with %N successful",
						   other_id, auth_method_names, AUTH_RSA);
			status = SUCCESS;
		}
		public->destroy(public);
	}
	else
	{
		DBG1(DBG_IKE, "no trusted public key found for '%D'", other_id);
	}
	chunk_free(&octets);
	return status;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_rsa_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	chunk_t octets, auth_data;
	status_t status = FAILED;
	private_key_t *private;
	identification_t *my_id;
	prf_t *prf;
	auth_info_t *auth;

	my_id = this->ike_sa->get_my_id(this->ike_sa);
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_method_names, AUTH_RSA);
	
	auth = this->ike_sa->get_my_auth(this->ike_sa);
	private = charon->credentials->get_private(charon->credentials, KEY_RSA,
											   my_id, auth);
	if (private == NULL)
	{
		DBG1(DBG_IKE, "no RSA private key found for '%D'", my_id);
		return NOT_FOUND;
	}
	prf = this->ike_sa->get_prf(this->ike_sa);
	prf->set_key(prf, this->ike_sa->get_skp_build(this->ike_sa));
	octets = build_tbs_octets(ike_sa_init, other_nonce, my_id, prf);
	/* we currently use always SHA1 for signatures, 
	 * TODO: support other hashes depending on configuration/auth */
	if (private->sign(private, SIGN_RSA_EMSA_PKCS1_SHA1, octets, &auth_data))
	{
		auth_payload_t *payload = auth_payload_create();
		payload->set_auth_method(payload, AUTH_RSA);
		payload->set_data(payload, auth_data);
		*auth_payload = payload;
		chunk_free(&auth_data);
		status = SUCCESS;
		DBG2(DBG_IKE, "successfully signed with RSA private key");
	}
	else
	{
		DBG1(DBG_IKE, "building RSA signature failed");
	}
	chunk_free(&octets);
	private->destroy(private);
	
	return status;
}

/**
 * Implementation of authenticator_t.destroy.
 */
static void destroy(private_rsa_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
rsa_authenticator_t *rsa_authenticator_create(ike_sa_t *ike_sa)
{
	private_rsa_authenticator_t *this = malloc_thing(private_rsa_authenticator_t);
	
	/* public functions */
	this->public.authenticator_interface.verify = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t*))verify;
	this->public.authenticator_interface.build = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t**))build;
	this->public.authenticator_interface.destroy = (void(*)(authenticator_t*))destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	
	return &this->public;
}
