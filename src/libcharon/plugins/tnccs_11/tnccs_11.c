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
#include <libtnctncs.h>

#include <daemon.h>
#include <debug.h>

#define TNC_SEND_BUFFER_SIZE	32

static chunk_t tnc_send_buffer[TNC_SEND_BUFFER_SIZE];

/**
 * Buffers TNCCS batch to be sent (TODO make the buffer scalable)
 */
static TNC_Result buffer_batch(u_int32_t id, const char *data, size_t len)
{
	if (id >= TNC_SEND_BUFFER_SIZE)
	{
		DBG1(DBG_IKE, "TNCCS Batch with Connection ID %u cannot be stored in "
					  "send buffer with size %d", id, TNC_SEND_BUFFER_SIZE);
		return TNC_RESULT_FATAL;
	}
	if (tnc_send_buffer[id].ptr)
	{
		DBG1(DBG_IKE, "send buffer slot for Connection ID %u is already "
					  "occupied", id);
		return TNC_RESULT_FATAL;
	}
	tnc_send_buffer[id] = chunk_alloc(len);
	memcpy(tnc_send_buffer[id].ptr, data, len);

	return TNC_RESULT_SUCCESS;
}

/**
 * Retrieves TNCCS batch to be sent
 */
static bool retrieve_batch(u_int32_t id, chunk_t *batch)
{
	if (id >= TNC_SEND_BUFFER_SIZE)
	{
		DBG1(DBG_IKE, "TNCCS Batch with Connection ID %u cannot be retrieved from "
					  "send buffer with size %d", id, TNC_SEND_BUFFER_SIZE);
		return FALSE;
	}

	*batch = tnc_send_buffer[id];
	return TRUE;
}

/**
 * Frees TNCCS batch that was sent
 */
static void free_batch(u_int32_t id)
{
	if (id < TNC_SEND_BUFFER_SIZE)
	{
		chunk_free(&tnc_send_buffer[id]);
	}
}

/**
 * Define callback functions called by the libtnc library
 */
TNC_Result TNC_TNCC_SendBatch(libtnc_tncc_connection* conn, 
							  const char* messageBuffer, size_t messageLength)
{
	return buffer_batch(conn->connectionID, messageBuffer, messageLength);
}

TNC_Result TNC_TNCS_SendBatch(libtnc_tncs_connection* conn, 
							  const char* messageBuffer, size_t messageLength)
{
	return buffer_batch(conn->connectionID, messageBuffer, messageLength);
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

	/**
	 * TNCS Connection to IMVs
	 */
	libtnc_tncs_connection* tncs_connection;
};

METHOD(tls_t, process, status_t,
	private_tnccs_11_t *this, void *buf, size_t buflen)
{
	u_int32_t conn_id;

	if (this->is_server && !this->tncs_connection)
	{
		this->tncs_connection = libtnc_tncs_CreateConnection(NULL);
		if (!this->tncs_connection)
		{
			DBG1(DBG_IKE, "TNCS CreateConnection failed");
			return FAILED;
		}
		DBG1(DBG_IKE, "assigned TNCS Connection ID %u",
					   this->tncs_connection->connectionID);
		if (libtnc_tncs_BeginSession(this->tncs_connection) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IKE, "TNCS BeginSession failed");
			return FAILED;
		}
	}
	conn_id = this->is_server ? this->tncs_connection->connectionID
							  : this->tncc_connection->connectionID;

	DBG1(DBG_IKE, "received TNCCS Batch of %u bytes for Connection ID %u:",
				   buflen, conn_id);
	DBG1(DBG_IKE, "%.*s", buflen, buf);

	if (this->is_server)
	{
		if (libtnc_tncs_ReceiveBatch(this->tncs_connection, buf, buflen) !=
			TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IKE, "TNCS ReceiveBatch failed");
			return FAILED;
		}
	}
	else
	{
		if (libtnc_tncc_ReceiveBatch(this->tncc_connection, buf, buflen) !=
			TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IKE, "TNCC ReceiveBatch failed");
			return FAILED;
		}
	}
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_11_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	chunk_t batch;
	u_int32_t conn_id;
	size_t len;

	if (!this->is_server && !this->tncc_connection)
	{
		this->tncc_connection = libtnc_tncc_CreateConnection(NULL);
		if (!this->tncc_connection)
		{
			DBG1(DBG_IKE, "TNCC CreateConnection failed");
			return FAILED;
		}
		DBG1(DBG_IKE, "assigned TNCC Connection ID %u",
					   this->tncc_connection->connectionID);
		if (libtnc_tncc_BeginSession(this->tncc_connection) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IKE, "TNCC BeginSession failed");
			return FAILED;
		}
	}
	conn_id = this->is_server ? this->tncs_connection->connectionID
							  : this->tncc_connection->connectionID;
	
	if (!retrieve_batch(conn_id, &batch))
	{
		return FAILED;
	}
	len = *buflen;
	len = min(len, batch.len);
	*buflen = len;
	if (msglen)
	{
		*msglen = batch.len;
	}

	if (batch.len)
	{
		DBG1(DBG_IKE, "sending TNCCS Batch of %d bytes for Connection ID %u:",
					   batch.len, conn_id);
		DBG1(DBG_IKE, "%.*s", batch.len, batch.ptr);
		memcpy(buf, batch.ptr, len);
		free_batch(conn_id);
		return ALREADY_DONE;
	}
	else
	{
		return INVALID_STATE;
	}
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
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	char *group;
	identification_t *id;
	ike_sa_t *ike_sa;
	auth_cfg_t *auth;
	
	if (libtnc_tncs_HaveRecommendation(this->tncs_connection, &rec, &eval) ==
		TNC_RESULT_SUCCESS)
	{
		switch (rec)
		{
			case TNC_IMV_ACTION_RECOMMENDATION_ALLOW:
				DBG1(DBG_IKE, "TNC recommendation is allow");
				group = "allow";
				break;				
			case TNC_IMV_ACTION_RECOMMENDATION_ISOLATE:
				DBG1(DBG_IKE, "TNC recommendation is isolate");
				group = "isolate";
				break;
			case TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS:
			case TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION:
			default:
				DBG1(DBG_IKE, "TNC recommendation is none");
				return FALSE;
		}
		ike_sa = charon->bus->get_sa(charon->bus);
		if (ike_sa)
		{
			auth = ike_sa->get_auth_cfg(ike_sa, FALSE);
			id = identification_create_from_string(group);
			auth->add(auth, AUTH_RULE_GROUP, id);
			DBG1(DBG_IKE, "added group membership '%s'", group);
		}
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tnccs_11_t *this)
{
	return chunk_empty;
}

METHOD(tls_t, destroy, void,
	private_tnccs_11_t *this)
{
	if (this->is_server)
	{
		if (this->tncs_connection)
		{
			libtnc_tncs_DeleteConnection(this->tncs_connection);
		}
	}
	else
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

	return &this->public;
}
