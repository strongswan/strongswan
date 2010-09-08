/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "eap_tnc.h"
#include "tnc_if_tnccs.h"

#include <tls_eap.h>

#include <daemon.h>
#include <library.h>

typedef struct private_eap_tnc_t private_eap_tnc_t;

/**
 * Private data of an eap_tnc_t object.
 */
struct private_eap_tnc_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_tnc_t public;

	/**
	 * Number of EAP-TNC messages processed so far
	 */
	int processed;

	/**
	 * TLS stack, wrapped by EAP helper
	 */
	tls_eap_t *tls_eap;
};


/** Maximum number of EAP-TNC messages/fragments allowed */
#define MAX_MESSAGE_COUNT 2 
/** Default size of a EAP-TNC fragment */
#define MAX_FRAGMENT_LEN 50000

METHOD(eap_method_t, initiate, status_t,
	private_eap_tnc_t *this, eap_payload_t **out)
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
	private_eap_tnc_t *this, eap_payload_t *in, eap_payload_t **out)
{
	status_t status;
	chunk_t data;

	if (++this->processed > MAX_MESSAGE_COUNT)
	{
		DBG1(DBG_IKE, "EAP-TNC packet count exceeded (%d > %d)",
			 this->processed, MAX_MESSAGE_COUNT);
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
	private_eap_tnc_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_TNC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_tnc_t *this, chunk_t *msk)
{
	*msk = this->tls_eap->get_msk(this->tls_eap);
	if (msk->len)
	{
		return SUCCESS;
	}
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_tnc_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_tnc_t *this)
{
	this->tls_eap->destroy(this->tls_eap);
	free(this);
}

/**
 * Generic private constructor
 */
static eap_tnc_t *eap_tnc_create(identification_t *server,
								 identification_t *peer, bool is_server)
{
	private_eap_tnc_t *this;
	size_t frag_size;
	tls_t *tnc_if_tnccs;

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

	frag_size = lib->settings->get_int(lib->settings,
					"charon.plugins.eap-tnc.fragment_size", MAX_FRAGMENT_LEN);
	tnc_if_tnccs = tnc_if_tnccs_create(is_server, TLS_PURPOSE_EAP_TNC);
	if (!tnc_if_tnccs)
	{
		free(this);
		return NULL;
	}
	this->tls_eap = tls_eap_create(EAP_TNC, tnc_if_tnccs, frag_size);
	if (!this->tls_eap)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

eap_tnc_t *eap_tnc_create_server(identification_t *server,
								 identification_t *peer)
{
	return eap_tnc_create(server, peer, TRUE);
}

eap_tnc_t *eap_tnc_create_peer(identification_t *server,
							   identification_t *peer)
{
	return eap_tnc_create(server, peer, FALSE);
}
