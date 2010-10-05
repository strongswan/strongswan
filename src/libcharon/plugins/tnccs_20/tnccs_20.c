/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnccs_20.h"

#include <debug.h>

static chunk_t tncc_output;

typedef struct private_tnccs_20_t private_tnccs_20_t;

/**
 * Private data of a tnccs_20_t object.
 */
struct private_tnccs_20_t {

	/**
	 * Public tls_t interface.
	 */
	tls_t public;

	/**
	 * TNCC if TRUE, TNCS if FALSE
	 */
	bool is_server;
};

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_20_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	return ALREADY_DONE;
}

METHOD(tls_t, is_server, bool,
	private_tnccs_20_t *this)
{
	return this->is_server;
}

METHOD(tls_t, get_purpose, tls_purpose_t,
	private_tnccs_20_t *this)
{
	return TLS_PURPOSE_EAP_TNC;
}

METHOD(tls_t, is_complete, bool,
	private_tnccs_20_t *this)
{
	return FALSE;
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tnccs_20_t *this)
{
	return chunk_empty;
}

METHOD(tls_t, destroy, void,
	private_tnccs_20_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_t *tnccs_20_create(bool is_server)
{
	private_tnccs_20_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.is_server = _is_server,
			.get_purpose = _get_purpose,
			.is_complete = _is_complete,
			.get_eap_msk = _get_eap_msk,
			.destroy = _destroy,
		},
		.is_server = is_server,
	);

	return &this->public;
}
