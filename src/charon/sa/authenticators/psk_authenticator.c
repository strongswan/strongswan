/*
 * Copyright (C) 2005-2008 Martin Willi
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

#include "psk_authenticator.h"

#include <daemon.h>
#include <credentials/auth_info.h>


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
 * Implementation of authenticator_t.verify.
 */
static status_t verify(private_psk_authenticator_t *this, chunk_t ike_sa_init,
 					   chunk_t my_nonce, auth_payload_t *auth_payload)
{
	chunk_t auth_data, recv_auth_data;
	identification_t *my_id, *other_id;
	shared_key_t *key;
	enumerator_t *enumerator;
	bool authenticated = FALSE;
	int keys_found = 0;
	keymat_t *keymat;
	
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	recv_auth_data = auth_payload->get_data(auth_payload);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	enumerator = charon->credentials->create_shared_enumerator(
							charon->credentials, SHARED_IKE, my_id, other_id);
	while (!authenticated && enumerator->enumerate(enumerator, &key, NULL, NULL))
	{
		keys_found++;
		
		auth_data = keymat->get_psk_sig(keymat, TRUE, ike_sa_init, my_nonce,
										key->get_key(key), other_id);
		if (auth_data.len && chunk_equals(auth_data, recv_auth_data))
		{
			DBG1(DBG_IKE, "authentication of '%D' with %N successful",
				 other_id, auth_method_names, AUTH_PSK);
			authenticated = TRUE;
		}
		chunk_free(&auth_data);
	}
	enumerator->destroy(enumerator);
	
	if (!authenticated)
	{
		if (keys_found == 0)
		{
			DBG1(DBG_IKE, "no shared key found for '%D' - '%D'", my_id, other_id);
			return NOT_FOUND;
		}
		DBG1(DBG_IKE, "tried %d shared key%s for '%D' - '%D', but MAC mismatched",
			 keys_found, keys_found == 1 ? "" : "s", my_id, other_id);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_psk_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	identification_t *my_id, *other_id;
	shared_key_t *key;
	chunk_t auth_data;
	keymat_t *keymat;
	
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_method_names, AUTH_PSK);
	key = charon->credentials->get_shared(charon->credentials, SHARED_IKE,
										  my_id, other_id);
	if (key == NULL)
	{
		DBG1(DBG_IKE, "no shared key found for '%D' - '%D'", my_id, other_id);
		return NOT_FOUND;
	}
	auth_data = keymat->get_psk_sig(keymat, FALSE, ike_sa_init, other_nonce,
									key->get_key(key), my_id);
	key->destroy(key);
	DBG2(DBG_IKE, "successfully created shared key MAC");
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
