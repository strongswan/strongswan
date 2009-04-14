/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
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

#include "pubkey_authenticator.h"

#include <daemon.h>
#include <encoding/payloads/auth_payload.h>

typedef struct private_pubkey_authenticator_t private_pubkey_authenticator_t;

/**
 * Private data of an pubkey_authenticator_t object.
 */
struct private_pubkey_authenticator_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	pubkey_authenticator_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * nonce to include in AUTH calculation
	 */
	chunk_t nonce;
	
	/**
	 * IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t ike_sa_init;
};

/**
 * Implementation of authenticator_t.build for builder
 */
static status_t build(private_pubkey_authenticator_t *this, message_t *message)
{
	chunk_t octets, auth_data;
	status_t status = FAILED;
	private_key_t *private;
	identification_t *id;
	auth_cfg_t *auth;
	auth_payload_t *auth_payload;
	auth_method_t auth_method;
	signature_scheme_t scheme;
	keymat_t *keymat;

	id = this->ike_sa->get_my_id(this->ike_sa);
	auth = this->ike_sa->get_auth_cfg(this->ike_sa, TRUE);
	private = charon->credentials->get_private(charon->credentials, KEY_ANY,
											   id, auth);
	if (private == NULL)
	{
		DBG1(DBG_IKE, "no private key found for '%D'", id);
		return NOT_FOUND;
	}
	
	switch (private->get_type(private))
	{
		case KEY_RSA:
			/* we currently use always SHA1 for signatures, 
			 * TODO: support other hashes depending on configuration/auth */
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			auth_method = AUTH_RSA;
			break;
		case KEY_ECDSA:
			/* we try to deduct the signature scheme from the keysize */
			switch (private->get_keysize(private))
			{
				case 32:
					scheme = SIGN_ECDSA_256; 
					auth_method = AUTH_ECDSA_256;
					break;
				case 48:
					scheme = SIGN_ECDSA_384;
					auth_method = AUTH_ECDSA_384;
					break;
				case 66:
					scheme = SIGN_ECDSA_521;
					auth_method = AUTH_ECDSA_521;
					break;
				default:
					DBG1(DBG_IKE, "%d bit ECDSA private key size not supported",
							private->get_keysize(private));
					return status;
			}
			break;
		default:
			DBG1(DBG_IKE, "private key of type %N not supported",
					key_type_names, private->get_type(private));
			return status;
	}
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	octets = keymat->get_auth_octets(keymat, FALSE, this->ike_sa_init,
									 this->nonce, id);
	if (private->sign(private, scheme, octets, &auth_data))
	{
		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, auth_method);
		auth_payload->set_data(auth_payload, auth_data);
		chunk_free(&auth_data);
		message->add_payload(message, (payload_t*)auth_payload);
		status = SUCCESS;
	}
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N %s", id,
		 auth_method_names, auth_method, 
		 (status == SUCCESS)? "successful":"failed");
	chunk_free(&octets);
	private->destroy(private);
	
	return status;
}

/**
 * Implementation of authenticator_t.process for verifier
 */
static status_t process(private_pubkey_authenticator_t *this, message_t *message)
{
	public_key_t *public;
	auth_method_t auth_method;
	auth_payload_t *auth_payload;
	chunk_t auth_data, octets;
	identification_t *id;
	auth_cfg_t *auth, *current_auth;
	enumerator_t *enumerator;
	key_type_t key_type = KEY_ECDSA;
	signature_scheme_t scheme;
	status_t status = NOT_FOUND;
	keymat_t *keymat;
	
	auth_payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	if (!auth_payload)
	{
		return FAILED;
	}
	auth_method = auth_payload->get_auth_method(auth_payload);
	switch (auth_method)
	{
		case AUTH_RSA:
			/* We currently accept SHA1 signatures only
			 * TODO: allow other hash algorithms and note it in "auth" */
			key_type = KEY_RSA;
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			break;
		case AUTH_ECDSA_256:
			scheme = SIGN_ECDSA_256;
			break;
		case AUTH_ECDSA_384:
			scheme = SIGN_ECDSA_384;
			break;
		case AUTH_ECDSA_521:
			scheme = SIGN_ECDSA_521;
			break;
		default:
			return INVALID_ARG;
	}
	auth_data = auth_payload->get_data(auth_payload);
	id = this->ike_sa->get_other_id(this->ike_sa);
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	octets = keymat->get_auth_octets(keymat, TRUE, this->ike_sa_init,
									 this->nonce, id);
	auth = this->ike_sa->get_auth_cfg(this->ike_sa, FALSE);
	enumerator = charon->credentials->create_public_enumerator(
										charon->credentials, key_type, id, auth);
	while (enumerator->enumerate(enumerator, &public, &current_auth))
	{
		if (public->verify(public, scheme, octets, auth_data))
		{
			DBG1(DBG_IKE, "authentication of '%D' with %N successful",
						   id, auth_method_names, auth_method);
			status = SUCCESS;
			auth->merge(auth, current_auth, FALSE);
			auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
			break;
		}
		else
		{
			status = FAILED;
			DBG1(DBG_IKE, "signature validation failed, looking for another key");
		}
	}
	enumerator->destroy(enumerator);
	chunk_free(&octets);
	if (status == NOT_FOUND)
	{
		DBG1(DBG_IKE, "no trusted %N public key found for '%D'",
			 key_type_names, key_type, id);
	}
	return status;
}

/**
 * Implementation of authenticator_t.process for builder
 * Implementation of authenticator_t.build for verifier
 */
static status_t return_failed()
{
	return FAILED;
}

/**
 * Implementation of authenticator_t.destroy.
 */
static void destroy(private_pubkey_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
pubkey_authenticator_t *pubkey_authenticator_create_builder(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_init)
{
	private_pubkey_authenticator_t *this = malloc_thing(private_pubkey_authenticator_t);
	
	this->public.authenticator.build = (status_t(*)(authenticator_t*, message_t *message))build;
	this->public.authenticator.process = (status_t(*)(authenticator_t*, message_t *message))return_failed;
	this->public.authenticator.destroy = (void(*)(authenticator_t*))destroy;
	
	this->ike_sa = ike_sa;
	this->ike_sa_init = sent_init;
	this->nonce = received_nonce;
	
	return &this->public;
}

/*
 * Described in header.
 */
pubkey_authenticator_t *pubkey_authenticator_create_verifier(ike_sa_t *ike_sa,
									chunk_t sent_nonce, chunk_t received_init)
{
	private_pubkey_authenticator_t *this = malloc_thing(private_pubkey_authenticator_t);
	
	this->public.authenticator.build = (status_t(*)(authenticator_t*, message_t *message))return_failed;
	this->public.authenticator.process = (status_t(*)(authenticator_t*, message_t *message))process;
	this->public.authenticator.destroy = (void(*)(authenticator_t*))destroy;
	
	this->ike_sa = ike_sa;
	this->ike_sa_init = received_init;
	this->nonce = sent_nonce;
	
	return &this->public;
}
