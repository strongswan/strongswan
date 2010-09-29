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

#include "tnccs_11.h"

#include <libtnctncc.h>

#include <debug.h>

static chunk_t tncc_output;

/**
 * Define callback function called by the libtnc library
 */
TNC_Result TNC_TNCC_SendBatch(libtnc_tncc_connection* conn, 
							  const char* messageBuffer, size_t messageLength)
{
	chunk_free(&tncc_output);
	tncc_output = chunk_alloc(messageLength);
	memcpy(tncc_output.ptr, messageBuffer, messageLength);

	return TNC_RESULT_SUCCESS;
}

typedef struct private_tnccs_11_t private_tnccs_11_t;

/**
 * Private data of a tnccs_11_t object.
 */
struct private_tnccs_11_t {

	/**
	 * Public tls_t interface.
	 */
	tls_t public;

	/**
	 * TNCC if TRUE, TNCS if FALSE
	 */
	bool is_server;

	/**
	 * TNCC Connection to IMCs
	 */
	libtnc_tncc_connection* tncc_connection;
};

METHOD(tls_t, process, status_t,
	private_tnccs_11_t *this, void *buf, size_t buflen)
{
	chunk_t in = { buf, buflen };

	/* TODO */
	DBG1(DBG_IKE, "received TNCCS-Batch: %B", &in);
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_11_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	size_t len = *buflen;

	if (!this->is_server && !this->tncc_connection)
	{
		this->tncc_connection = libtnc_tncc_CreateConnection(NULL);
		if (!this->tncc_connection)
		{
			DBG1(DBG_IKE, "TNCC CreateConnection failed");
			return FAILED;
		}
		DBG1(DBG_IKE, "assigned TNC ConnectionID: %d",
			 this->tncc_connection->connectionID);
		if (libtnc_tncc_BeginSession(this->tncc_connection) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IKE, "TNCC BeginSession failed");
			return FAILED;
		}
	}
		
	if (msglen)
	{
		*msglen = tncc_output.len;
	}
	DBG1(DBG_IKE, "sending TNCCS-Batch: %B", &tncc_output);
	len = min(len, tncc_output.len);
	memcpy(buf, tncc_output.ptr, len);
	chunk_free(&tncc_output);
	*buflen = len;

	return ALREADY_DONE;
}

METHOD(tls_t, is_server, bool,
	private_tnccs_11_t *this)
{
	return this->is_server;
}

METHOD(tls_t, get_purpose, tls_purpose_t,
	private_tnccs_11_t *this)
{
	return TLS_PURPOSE_EAP_TNC;
}

METHOD(tls_t, is_complete, bool,
	private_tnccs_11_t *this)
{
	/* TODO */
	return FALSE;
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tnccs_11_t *this)
{
	return chunk_empty;
}

METHOD(tls_t, destroy, void,
	private_tnccs_11_t *this)
{
	if (!this->is_server)
	{
		if (this->tncc_connection)
		{
			libtnc_tncc_DeleteConnection(this->tncc_connection);
		}
		libtnc_tncc_Terminate();
	}
	free(this);
}

/**
 * See header
 */
tls_t *tnccs_11_create(bool is_server)
{
	private_tnccs_11_t *this;

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

	if (!is_server)
	{
		int imc_count;

		imc_count = libtnc_imc_load_config("/etc/tnc_config");
		if (imc_count < 0)
		{
			free(this);
			DBG1(DBG_IKE, "TNC IMC initialization failed");
			return NULL;
		}
		else
		{
			DBG1(DBG_IKE, "loaded %d TNC IMC instances", imc_count);
		}
		libtnc_tncc_PreferredLanguage("en");
	}
	return &this->public;
}
