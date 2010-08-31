/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "eap_tls.h"

#include <tls_eap.h>

#include <daemon.h>
#include <library.h>

typedef struct private_eap_tls_t private_eap_tls_t;

/**
 * Private data of an eap_tls_t object.
 */
struct private_eap_tls_t {

	/**
	 * Public interface.
	 */
	eap_tls_t public;

	/**
	 * Number of EAP-TLS messages processed so far
	 */
	int processed;

	/**
	 * TLS stack, wrapped by EAP helper
	 */
	tls_eap_t *tls_eap;
};

/** Maximum number of EAP-TLS messages/fragments allowed */
#define MAX_EAP_TLS_MESSAGE_COUNT 24

METHOD(eap_method_t, initiate, status_t,
	private_eap_tls_t *this, eap_payload_t **out)
{
	chunk_t data;

	if (this->tls_eap->initiate(this->tls_eap, &data) == NEED_MORE)
	{
		*out = eap_payload_create_data(data);
		free(data.ptr);
		return NEED_MORE;
	}
	return FAILED;
}

METHOD(eap_method_t, process, status_t,
	private_eap_tls_t *this, eap_payload_t *in, eap_payload_t **out)
{
	status_t status;
	chunk_t data;

	if (++this->processed > MAX_EAP_TLS_MESSAGE_COUNT)
	{
		DBG1(DBG_IKE, "EAP-TLS packet count exceeded (%d > %d)",
			 this->processed, MAX_EAP_TLS_MESSAGE_COUNT);
		return FAILED;
	}
	data = in->get_data(in);
	status = this->tls_eap->process(this->tls_eap, data, &data);
	if (status == NEED_MORE)
	{
		*out = eap_payload_create_data(data);
		free(data.ptr);
	}
	return status;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_tls_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_TLS;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_tls_t *this, chunk_t *msk)
{
	*msk = this->tls_eap->get_msk(this->tls_eap);
	if (msk->len)
	{
		return SUCCESS;
	}
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_tls_t *this)
{
	return TRUE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_tls_t *this)
{
	this->tls_eap->destroy(this->tls_eap);
	free(this);
}

/**
 * Generic private constructor
 */
static eap_tls_t *eap_tls_create(identification_t *server,
								 identification_t *peer, bool is_server)
{
	private_eap_tls_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.destroy = _destroy,
			},
		},
	);

	this->tls_eap = tls_eap_create(EAP_TLS, is_server, server, peer, NULL);
	if (!this->tls_eap)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

eap_tls_t *eap_tls_create_server(identification_t *server,
								 identification_t *peer)
{
	return eap_tls_create(server, peer, TRUE);
}

eap_tls_t *eap_tls_create_peer(identification_t *server,
							   identification_t *peer)
{
	return eap_tls_create(server, peer, FALSE);
}
