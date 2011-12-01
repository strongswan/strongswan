/*
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
 */

#include "xauth_authenticator.h"

#include <daemon.h>
#include <encoding/payloads/cp_payload.h>
#include <sa/keymat_v2.h>

typedef struct private_xauth_authenticator_t private_xauth_authenticator_t;

/**
 * Private data of an xauth_authenticator_t object.
 */
struct private_xauth_authenticator_t {

	/**
	 * Public authenticator_t interface.
	 */
	xauth_authenticator_t public;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * The payload to send
	 */
	cp_payload_t *cp_payload;

	/**
	 * Whether the authenticator is for an XAUTH server or client
	 */
	xauth_role_t role;
};

/**
 * load an XAuth method
 */
static xauth_method_t *load_method(private_xauth_authenticator_t *this,
							xauth_type_t type, u_int32_t vendor)
{
	identification_t *server, *peer, *aaa;
	auth_cfg_t *auth;

	if (this->role == XAUTH_SERVER)
	{
		server = this->ike_sa->get_my_id(this->ike_sa);
		peer = this->ike_sa->get_other_id(this->ike_sa);
		auth = this->ike_sa->get_auth_cfg(this->ike_sa, FALSE);
	}
	else
	{
		server = this->ike_sa->get_other_id(this->ike_sa);
		peer = this->ike_sa->get_my_id(this->ike_sa);
		auth = this->ike_sa->get_auth_cfg(this->ike_sa, TRUE);
	}
	aaa = auth->get(auth, AUTH_RULE_AAA_IDENTITY);
	if (aaa)
	{
		server = aaa;
	}
	return charon->xauth->create_instance(charon->xauth, type, vendor,
										this->role, server, peer);
}

METHOD(authenticator_t, build, status_t,
	private_xauth_authenticator_t *this, message_t *message)
{
	if(this->cp_payload != NULL)
	{
		message->add_payload(message, (payload_t *)this->cp_payload);
		return NEED_MORE;
	}
	return SUCCESS;
}

METHOD(authenticator_t, process, status_t,
	private_xauth_authenticator_t *this, message_t *message)
{
	xauth_method_t *xauth_method = NULL;
	cp_payload_t *cp_in, *cp_out;
	status_t status = FAILED;

	cp_in = (cp_payload_t *)message->get_payload(message, CONFIGURATION_V1);

	xauth_method = load_method(this, XAUTH_NULL, 0);

	if(xauth_method != NULL)
	{
		status = xauth_method->process(xauth_method, cp_in, &cp_out);
		if(status == NEED_MORE)
		{
			this->cp_payload = cp_out;
		}
		else
		{
			xauth_method->destroy(xauth_method);
		}
	}
	else
	{
		DBG1(DBG_IKE, "Couldn't locate valid xauth method.");
	}

	return status;
}

METHOD(authenticator_t, destroy, void,
	private_xauth_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
xauth_authenticator_t *xauth_authenticator_create_builder(ike_sa_t *ike_sa)
{
	private_xauth_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build,
				.process = _process,
				.is_mutual = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.cp_payload = NULL,
		.role = XAUTH_PEER,
	);

	return &this->public;
}

/*
 * Described in header.
 */
xauth_authenticator_t *xauth_authenticator_create_verifier(ike_sa_t *ike_sa)
{
	private_xauth_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build,
				.process = _process,
				.is_mutual = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.cp_payload = NULL,
		.role = XAUTH_SERVER,
	);

	return &this->public;
}
