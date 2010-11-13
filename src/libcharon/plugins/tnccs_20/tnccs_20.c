/*
 * Copyright (C) 2010 Sansar Choinyanbuu
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
#include <daemon.h>
#include <threading/mutex.h>
#include <tnc/tncif.h>
#include <tnc/tnccs/tnccs.h>

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

	/**
	 * Connection ID assigned to this TNCCS connection
	 */
	TNC_ConnectionID connection_id;

	/**
	 * Batch being constructed
	 */
	chunk_t batch;

	/**
	 * Mutex locking the batch in construction
	 */
	mutex_t *mutex;

	/**
	 * Set of IMV recommendations  (TNC Server only)
	 */
	recommendations_t *recs;
};

METHOD(tnccs_t, send_message, void,
	private_tnccs_20_t* this, TNC_BufferReference message,
							  TNC_UInt32 message_len,
							  TNC_MessageType message_type)
{
	chunk_t msg = { message, message_len };

	DBG1(DBG_TNC, "TNCCS 2.0 send message");
	this->mutex->lock(this->mutex);
	this->batch = chunk_cat("mc", this->batch, msg);
	this->mutex->unlock(this->mutex);
}

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	char *pos;
	size_t len;

	if (this->is_server && !this->connection_id)
	{
		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
								(tnccs_t*)this,	_send_message,  &this->recs);
		if (!this->connection_id)
		{
			return FAILED;
		}
		charon->imvs->notify_connection_change(charon->imvs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
	}
	DBG1(DBG_TNC, "received TNCCS Batch (%u bytes) for Connection ID %u",
				   buflen, this->connection_id);
	DBG3(DBG_TNC, "%.*s", buflen, buf);
	pos = strchr(buf, '|');
	if (pos)
	{
		pos++;
		len = buflen - (pos - (char*)buf);
	}
	else
	{
		pos = buf;
		len = buflen;
	}
	DBG1(DBG_TNC, "received message '%.*s'", len, pos);
	if (this->is_server)
	{
		charon->imvs->receive_message(charon->imvs, this->connection_id,
									  pos, len, 0x0080ab31);
		charon->imvs->batch_ending(charon->imvs, this->connection_id);
	}
	else
	{
		charon->imcs->receive_message(charon->imcs, this->connection_id,
									  pos, len, 0x0080ab31);
		charon->imcs->batch_ending(charon->imcs, this->connection_id);
	}
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_20_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	char *msg = this->is_server ? "tncs->tncc 2.0|" : "tncc->tncs 2.0|";
	size_t len;

	this->mutex->lock(this->mutex);
	this->batch = chunk_cat("cm", chunk_create(msg, strlen(msg)), this->batch);
	this->mutex->unlock(this->mutex);

	if (!this->is_server && !this->connection_id)
	{
		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
										(tnccs_t*)this, _send_message, NULL);
		if (!this->connection_id)
		{
			return FAILED;
		}
		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
		charon->imcs->begin_handshake(charon->imcs, this->connection_id);
	}

	this->mutex->lock(this->mutex);
	len = this->batch.len;
	*msglen = len;
	*buflen = len;
	memcpy(buf, this->batch.ptr, len);
	chunk_free(&this->batch);
	this->mutex->unlock(this->mutex);

	DBG1(DBG_TNC, "sending TNCCS Batch (%d bytes) for Connection ID %u",
				   len, this->connection_id);
	DBG3(DBG_TNC, "%.*s", len, buf);

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
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;

	if (this->recs && this->recs->have_recommendation(this->recs, &rec, &eval))
	{
		return charon->imvs->enforce_recommendation(charon->imvs, rec);
	}
	else
	{
		return FALSE;
	}
}

METHOD(tls_t, get_eap_msk, chunk_t,
	private_tnccs_20_t *this)
{
	return chunk_empty;
}

METHOD(tls_t, destroy, void,
	private_tnccs_20_t *this)
{
	charon->tnccs->remove_connection(charon->tnccs, this->connection_id);
	this->mutex->destroy(this->mutex);
	free(this->batch.ptr);
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
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
