/**
 * @file rsa_authenticator.c
 *
 * @brief Implementation of rsa_authenticator_t.
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

#include "rsa_authenticator.h"

#include <daemon.h>


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
	status_t status;
	chunk_t auth_data, octets;
	identification_t *other_id;
	ca_info_t *issuer;
	prf_t *prf;
	
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	
	if (auth_payload->get_auth_method(auth_payload) != AUTH_RSA)
	{
		return INVALID_ARG;
	}
	auth_data = auth_payload->get_data(auth_payload);
	prf = this->ike_sa->get_prf(this->ike_sa);
	prf->set_key(prf, this->ike_sa->get_skp_verify(this->ike_sa));
	octets = build_tbs_octets(ike_sa_init, my_nonce, other_id, prf);
	status = charon->credentials->verify_signature(charon->credentials,
								  octets, auth_data, other_id, &issuer);
	chunk_free(&octets);
	
	if (status == SUCCESS)
	{
		this->ike_sa->set_other_ca(this->ike_sa, issuer);
		DBG1(DBG_IKE, "authentication of '%D' with %N successful",
					   other_id, auth_method_names, AUTH_RSA);
	}
	return status;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_rsa_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	chunk_t chunk;
	chunk_t octets;
	chunk_t auth_data;
	status_t status;
	rsa_public_key_t *my_pubkey;
	identification_t *my_id;
	prf_t *prf;

	my_id = this->ike_sa->get_my_id(this->ike_sa);
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_method_names, AUTH_RSA);
	DBG2(DBG_IKE, "looking for RSA public key belonging to '%D'...", my_id);

	my_pubkey = charon->credentials->get_rsa_public_key(charon->credentials, my_id);
	if (my_pubkey == NULL)
	{
		DBG1(DBG_IKE, "no RSA public key found for '%D'", my_id);
		return NOT_FOUND;
	}
	DBG2(DBG_IKE, "  matching RSA public key found");

	prf = this->ike_sa->get_prf(this->ike_sa);
	prf->set_key(prf, this->ike_sa->get_skp_build(this->ike_sa));
	octets = build_tbs_octets(ike_sa_init, other_nonce, my_id, prf);
	status = charon->credentials->rsa_signature(charon->credentials,
										my_pubkey, HASH_SHA1, octets, &auth_data);
	chunk_free(&octets);

	if (status != SUCCESS)
	{
		DBG1(DBG_IKE, "building RSA signature with SHA-1 hash failed");
		return status;
	}
	DBG2(DBG_IKE, "successfully signed with RSA private key");
	
	*auth_payload = auth_payload_create();
	(*auth_payload)->set_auth_method(*auth_payload, AUTH_RSA);
	(*auth_payload)->set_data(*auth_payload, auth_data);
	chunk_free(&auth_data);
	return SUCCESS;
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
