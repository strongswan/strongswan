/*
 * Copyright (C) 2010 Andreas Steffen
 * Copyright (C) 2010 HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_if_tnccs.h"

#include <debug.h>

typedef struct private_tnc_if_tnccs_t private_tnc_if_tnccs_t;

/**
 * Private data of a tnc_if_tnccs_t object.
 */
struct private_tnc_if_tnccs_t {

	/**
	 * Public tls_t interface.
	 */
	tls_t public;

	/**
	 * Role this TNC IF-TNCCS stack acts as.
	 */
	bool is_server;

	/**
	 * TLS stack purpose, as given to constructor
	 */
	tls_purpose_t purpose;
};

METHOD(tls_t, process, status_t,
	private_tnc_if_tnccs_t *this, void *buf, size_t buflen)
{
	chunk_t in = { buf, buflen };

	/* TODO */
	DBG1(DBG_IKE, "received TNCCS-Batch: %B", &in);
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnc_if_tnccs_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	char output[] = 
		"<?xml version=\"1.0\"?>\n"
		"<TNCCS-Batch BatchId=\"1\" Recipient=\"TNCS\"\n"
		"xmlns=\"http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS#\"\n"
		"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
		"xsi:schemaLocation=\"http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS#\n"
		"https://www.trustedcomputinggroup.org/XML/SCHEMA/TNCCS_1.0.xsd\">\n"
		"</TNCCS-Batch>\n";

	size_t len = strlen(output);
	chunk_t out = { output, len };	

	/* TODO */
	DBG1(DBG_IKE, "sending TNCCS-Batch: %B", &out);
	*buflen = len;
	*msglen = len;
	memcpy(buf, output, len);

	return ALREADY_DONE;
}

METHOD(tls_t, is_server, bool,
	private_tnc_if_tnccs_t *this)
{
	return this->is_server;
}

METHOD(tls_t, get_purpose, tls_purpose_t,
	private_tnc_if_tnccs_t *this)
{
	return this->purpose;
}

METHOD(tls_t, is_complete, bool,
	private_tnc_if_tnccs_t *this)
{
	/* TODO */
	return FALSE;
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tnc_if_tnccs_t *this)
{
	return chunk_empty;
}

METHOD(tls_t, destroy, void,
	private_tnc_if_tnccs_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_t *tnc_if_tnccs_create(bool is_server, tls_purpose_t purpose)
{
	private_tnc_if_tnccs_t *this;

	switch (purpose)
	{
		case TLS_PURPOSE_EAP_TNC:
			break;
		default:
			return NULL;
	}

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
		.purpose = purpose,
	);

	return &this->public;
}
