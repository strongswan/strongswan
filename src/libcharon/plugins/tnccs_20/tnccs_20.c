/*
 * Copyright (C) 2010 Sansar Choinyanbuu
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
#include "tnccs_20_types.h"
#include "batch/pb_tnc_batch.h"
#include "messages/pb_tnc_message.h"
#include "messages/pb_pa_message.h"
#include "messages/pb_error_message.h"
#include "messages/pb_language_preference_message.h"

#include <debug.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <tnc/tncif.h>
#include <tnc/tncifimv_names.h>
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
	 * PB-TNC State Machine
	 */
	pb_tnc_state_t state;

	/**
	 * Connection ID assigned to this TNCCS connection
	 */
	TNC_ConnectionID connection_id;

	/**
	 * PB-TNC batch being constructed
	 */
	pb_tnc_batch_t *batch;

	/**
	 * Mutex locking the batch in construction
	 */
	mutex_t *mutex;

	/**
	 * Flag set by IMC/IMV RequestHandshakeRetry() function
	 */
	bool request_handshake_retry;

	/**
	 * Set of IMV recommendations  (TNC Server only)
	 */
	recommendations_t *recs;
};

METHOD(tnccs_t, send_message, void,
	private_tnccs_20_t* this, TNC_IMCID imc_id, TNC_IMVID imv_id,
							  TNC_BufferReference msg,
							  TNC_UInt32 msg_len,
							  TNC_MessageType msg_type)
{
    TNC_MessageSubtype msg_sub_type;
    TNC_VendorID msg_vendor_id;
	pb_tnc_message_t *pb_tnc_msg;
	pb_tnc_batch_type_t batch_type;

	msg_sub_type =   msg_type       & TNC_SUBTYPE_ANY;
	msg_vendor_id = (msg_type >> 8) & TNC_VENDORID_ANY;

	pb_tnc_msg = pb_pa_message_create(msg_vendor_id, msg_sub_type, imc_id, imv_id,
									  chunk_create(msg, msg_len));

	/* adding PA message to SDATA or CDATA batch only */
	batch_type = this->is_server ? PB_BATCH_SDATA : PB_BATCH_CDATA;
	this->mutex->lock(this->mutex);
	if (!this->batch)
	{
		this->batch = pb_tnc_batch_create(this->is_server, batch_type);
	}
	if (this->batch->get_type(this->batch) == batch_type)
	{
		this->batch->add_message(this->batch, pb_tnc_msg);
	}
	else
	{
		pb_tnc_msg->destroy(pb_tnc_msg);
	}
	this->mutex->unlock(this->mutex);
}

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	chunk_t data;
	pb_tnc_batch_t *batch;
	pb_tnc_message_t *msg;
	pb_tnc_state_t old_state;
	enumerator_t *enumerator;
	status_t status;

	if (this->is_server && !this->connection_id)
	{
		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
								(tnccs_t*)this,	_send_message,
								&this->request_handshake_retry, &this->recs);
		if (!this->connection_id)
		{
			return FAILED;
		}
		charon->imvs->notify_connection_change(charon->imvs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
	}
	data = chunk_create(buf, buflen);
	DBG1(DBG_TNC, "received TNCCS Batch (%u bytes) for Connection ID %u",
				   data.len, this->connection_id);
	DBG3(DBG_TNC, "%B", &data);  
	batch = pb_tnc_batch_create_from_data(this->is_server, data);

	old_state = this->state;
	status = batch->process(batch, &this->state);
	if (this->state != old_state)
	{
		DBG2(DBG_TNC, "PB-TNC state transition from '%N' to '%N'",
			 pb_tnc_state_names, old_state, pb_tnc_state_names, this->state);
	}
	switch (status)
	{
		case SUCCESS:
		default:
			break;
		case FAILED:
			if (this->batch)
			{
				DBG1(DBG_TNC, "cancelling PB-TNC %N Batch",
					pb_tnc_batch_type_names, this->batch->get_type(this->batch));
				this->batch->destroy(this->batch);
			 }
			this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_CLOSE);
			/* fall through */
		case VERIFY_ERROR:
			enumerator = batch->create_error_enumerator(batch);
			while (enumerator->enumerate(enumerator, &msg))
			{
				this->batch->add_message(this->batch, msg->get_ref(msg));
			}
			enumerator->destroy(enumerator);
	}
	batch->destroy(batch);

	if (this->is_server)
	{
		charon->imvs->batch_ending(charon->imvs, this->connection_id);
	}
	else
	{
		charon->imcs->batch_ending(charon->imcs, this->connection_id);
	}
	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_20_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	if (!this->is_server && !this->connection_id)
	{
		pb_tnc_message_t *msg;
		char *pref_lang;

		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
										(tnccs_t*)this, _send_message,
										&this->request_handshake_retry, NULL);
		if (!this->connection_id)
		{
			return FAILED;
		}

		/* Create PB-TNC Language Preference Message */
		pref_lang = charon->imcs->get_preferred_language(charon->imcs);
		msg = pb_language_preference_message_create(chunk_create(pref_lang,
													strlen(pref_lang)));
		this->mutex->lock(this->mutex);
		this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_CDATA);
		this->batch->add_message(this->batch, msg);
		this->mutex->unlock(this->mutex);

		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
		charon->imcs->begin_handshake(charon->imcs, this->connection_id);
	}

	if (this->batch)
	{
		pb_tnc_batch_type_t batch_type;
		pb_tnc_state_t old_state;
		status_t status;
 		chunk_t data;
		bool unexpected_batch_type = FALSE;

		batch_type = this->batch->get_type(this->batch);
		old_state = this->state;
		
		switch (this->state)
		{
			case PB_STATE_INIT:
				if (batch_type == PB_BATCH_CDATA)
				{
					this->state = PB_STATE_SERVER_WORKING;
					break;
				}
				if (batch_type == PB_BATCH_SDATA)
				{
					this->state = PB_STATE_CLIENT_WORKING;
					break;
				}
				if (batch_type == PB_BATCH_CLOSE)
				{
					this->state = PB_STATE_END;
					break;
				}
				unexpected_batch_type = TRUE;
				break;
			case PB_STATE_SERVER_WORKING:
				if (batch_type == PB_BATCH_SDATA)
				{
					this->state = PB_STATE_CLIENT_WORKING;
					break;
				}
				if (batch_type == PB_BATCH_RESULT)
				{
					this->state = PB_STATE_DECIDED;
					break;
				}
				if (batch_type == PB_BATCH_CRETRY ||
			   		batch_type == PB_BATCH_SRETRY)
				{
					break;
				}
				if (batch_type == PB_BATCH_CLOSE)
				{
					this->state = PB_STATE_END;
					break;
				}
				unexpected_batch_type = TRUE;
				break;
			case PB_STATE_CLIENT_WORKING:
				if (batch_type == PB_BATCH_CDATA)
				{
					this->state = PB_STATE_SERVER_WORKING;
					break;
				}
				if (batch_type == PB_BATCH_CRETRY)
				{
					break;
				}
				if (batch_type == PB_BATCH_CLOSE)
				{
					this->state = PB_STATE_END;
					break;
				}
				unexpected_batch_type = TRUE;
				break;
			case PB_STATE_DECIDED:
				if (batch_type == PB_BATCH_CRETRY ||
					batch_type == PB_BATCH_SRETRY)
				{
					this->state = PB_STATE_SERVER_WORKING;
					break;
				}
				if (batch_type == PB_BATCH_CLOSE)
				{
					this->state = PB_STATE_END;
					break;
				}
				unexpected_batch_type = TRUE;
				break;
			case PB_STATE_END:
				if (batch_type == PB_BATCH_CLOSE)
				{
					break;
				}
				unexpected_batch_type = TRUE;
		}

		this->mutex->lock(this->mutex);
		if (unexpected_batch_type)
		{
			DBG1(DBG_TNC, "cancelling unexpected PB-TNC Batch Type: %N",
				 pb_tnc_batch_type_names, batch_type);
			status = INVALID_STATE;
		}
		else
		{
			this->batch->build(this->batch);
			data = this->batch->get_encoding(this->batch);
			DBG1(DBG_TNC, "sending PB-TNC %N Batch (%d bytes) for Connection ID %u",
						   pb_tnc_batch_type_names, batch_type, data.len,
						   this->connection_id);
			DBG3(DBG_TNC, "%B", &data);

			*msglen = data.len;
			*buflen = data.len;
			memcpy(buf, data.ptr, data.len);
			status = ALREADY_DONE;
		}
		this->batch->destroy(this->batch);
		this->batch = NULL;
		this->mutex->unlock(this->mutex);

		if (this->state != old_state)
		{
			DBG2(DBG_TNC, "PB-TNC state transition from '%N' to '%N'",
				 pb_tnc_state_names, old_state, pb_tnc_state_names, this->state);
		}
		return status;
	}
	else
	{
		DBG1(DBG_TNC, "no TNCCS Batch to send");
		return INVALID_STATE;
	}
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
		DBG2(DBG_TNC, "Final recommendation '%N' and evaluation '%N'",
			 action_recommendation_names, rec, evaluation_result_names, eval);

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
	DESTROY_IF(this->batch);
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
		.state = PB_STATE_INIT,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
