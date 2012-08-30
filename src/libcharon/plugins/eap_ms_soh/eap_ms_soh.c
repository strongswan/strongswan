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

#include "eap_ms_soh.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_ms_soh_t private_eap_ms_soh_t;

/**
 * Private data of an eap_ms_soh_t object.
 */
struct private_eap_ms_soh_t {

	/**
	 * Public interface.
	 */
	eap_ms_soh_t public;

	/**
	 * Current EAP packet identifier
	 */
	u_int8_t identifier;
};

METHOD(eap_method_t, initiate, status_t,
	private_eap_ms_soh_t *this, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, process, status_t,
	private_eap_ms_soh_t *this, eap_payload_t *in, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_ms_soh_t *this, u_int32_t *vendor)
{
	*vendor = PEN_MICROSOFT;
	return EAP_MS_SOH;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_ms_soh_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, get_identifier, u_int8_t,
	private_eap_ms_soh_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_ms_soh_t *this, u_int8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_ms_soh_t *this)
{
	return TRUE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_ms_soh_t *this)
{
	free(this);
}

/**
 * Generic private constructor
 */
static private_eap_ms_soh_t *create_empty()
{
	private_eap_ms_soh_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
	);

	return this;
}

eap_ms_soh_t *eap_ms_soh_create_server(identification_t *server,
									   identification_t *peer)
{
	private_eap_ms_soh_t *this;

	this = create_empty();

	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

eap_ms_soh_t *eap_ms_soh_create_peer(identification_t *server,
									identification_t *peer)
{
	return &create_empty()->public;
}
