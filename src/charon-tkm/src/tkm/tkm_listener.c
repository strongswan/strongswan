/*
 * Copyrigth (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <daemon.h>
#include <encoding/payloads/auth_payload.h>
#include <utils/chunk.h>
#include <tkm/types.h>
#include <tkm/constants.h>
#include <tkm/client.h>

#include "tkm_listener.h"
#include "tkm_keymat.h"
#include "tkm_utils.h"

typedef struct private_tkm_listener_t private_tkm_listener_t;

/**
 * Private data of a tkm_listener_t object.
 */
struct private_tkm_listener_t {

	/**
	 * Public tkm_listener_t interface.
	 */
	tkm_listener_t public;

};

METHOD(listener_t, authorize, bool,
	private_tkm_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	if (!final)
	{
		return TRUE;
	}

	tkm_keymat_t * const keymat = (tkm_keymat_t*)ike_sa->get_keymat(ike_sa);
	const isa_id_type isa_id = keymat->get_isa_id(keymat);
	DBG1(DBG_IKE, "TKM authorize listener called for ISA context %llu", isa_id);

	const chunk_t * const auth = keymat->get_auth_payload(keymat);
	if (!auth->ptr)
	{
		DBG1(DBG_IKE, "no AUTHENTICATION data available");
		*success = FALSE;
	}

	signature_type signature;
	chunk_to_sequence(auth, &signature);
	if (ike_isa_auth_psk(isa_id, signature) != TKM_OK)
	{
		DBG1(DBG_IKE, "TKM based authentication failed"
			 " for ISA context %llu", isa_id);
		*success = FALSE;
	}
	else
	{
		DBG1(DBG_IKE, "TKM based authentication successful"
			 " for ISA context %llu", isa_id);
		*success = TRUE;
	}

	return TRUE;
}

METHOD(listener_t, message, bool,
	private_tkm_listener_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	if (!incoming || !plain || message->get_exchange_type(message) != IKE_AUTH)
	{
		return TRUE;
	}

	tkm_keymat_t * const keymat = (tkm_keymat_t*)ike_sa->get_keymat(ike_sa);
	const isa_id_type isa_id = keymat->get_isa_id(keymat);
	DBG1(DBG_IKE, "saving AUTHENTICATION payload for authorize hook"
		   " (ISA context %llu)", isa_id);

	auth_payload_t * const auth_payload =
		(auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	if (auth_payload)
	{
		const chunk_t auth_data = auth_payload->get_data(auth_payload);
		keymat->set_auth_payload(keymat, &auth_data);
	}
	else
	{
		DBG1(DBG_IKE, "unable to extract AUTHENTICATION payload, authorize will"
			 " fail");
	}

	return TRUE;
}

METHOD(tkm_listener_t, destroy, void,
	private_tkm_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
tkm_listener_t *tkm_listener_create()
{
	private_tkm_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
				.message = _message,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
