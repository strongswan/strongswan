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
#include "messages/pb_assessment_result_message.h"
#include "messages/pb_access_recommendation_message.h"
#include "messages/pb_reason_string_message.h"
#include "messages/pb_language_preference_message.h"
#include "state_machine/pb_tnc_state_machine.h"

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
	pb_tnc_state_machine_t *state_machine;

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

static void handle_message(private_tnccs_20_t *this, pb_tnc_message_t *msg)
{
	switch (msg->get_type(msg))
	{
		case PB_MSG_EXPERIMENTAL:
			/* for experiments */
			break;
		case PB_MSG_PA:
		{
			pb_pa_message_t *pa_msg;
			TNC_MessageType msg_type;
			u_int32_t vendor_id, subtype;
			chunk_t msg_body;

			pa_msg = (pb_pa_message_t*)msg;
			vendor_id = pa_msg->get_vendor_id(pa_msg, &subtype);
			msg_type = (vendor_id << 8) | (subtype & 0xff);
			msg_body = pa_msg->get_body(pa_msg);

			DBG2(DBG_TNC, "handling message type 0x%08x", msg_type);

			if (this->is_server)
			{
				charon->imvs->receive_message(charon->imvs,
				this->connection_id, msg_body.ptr, msg_body.len, msg_type);
			}
			else
			{
				charon->imcs->receive_message(charon->imcs,
				this->connection_id, msg_body.ptr, msg_body.len,msg_type);
			}
			break;
		}
		case PB_MSG_ASSESSMENT_RESULT:
		{
			pb_assessment_result_message_t *assess_msg;
			u_int32_t result;

			assess_msg = (pb_assessment_result_message_t*)msg;
			result = assess_msg->get_assessment_result(assess_msg);
			DBG1(DBG_TNC, "assessment result is '%N'",
						   evaluation_result_names, result);
			break;
		}
		case PB_MSG_ACCESS_RECOMMENDATION:
		{
			pb_access_recommendation_message_t *rec_msg;
			u_int16_t rec;

			rec_msg = (pb_access_recommendation_message_t*)msg;
			rec = rec_msg->get_access_recommendation(rec_msg);
			DBG1(DBG_TNC, "access recommendation is '%N'",
						   action_recommendation_names, rec);
				break;
		}
		case PB_MSG_REMEDIATION_PARAMETERS:
		{
			/* TODO : Remediation parameters message processing */
			break;
		}
		case PB_MSG_ERROR:
		{
			pb_error_message_t *err_msg;
			bool fatal;
			u_int32_t vendor_id;
			u_int16_t error_code;

			err_msg = (pb_error_message_t*)msg;
			fatal = err_msg->get_fatal_flag(err_msg);
			vendor_id = err_msg->get_vendor_id(err_msg);
			error_code = err_msg->get_error_code(err_msg);

			if (vendor_id == IETF_VENDOR_ID)
			{
				switch (error_code)
				{
					case PB_ERROR_INVALID_PARAMETER:
					case PB_ERROR_UNSUPPORTED_MANDATORY_MESSAGE:
						DBG1(DBG_TNC, "received %s PB-TNC Error '%N' "
									  "(offset %u bytes)",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code,
									  err_msg->get_offset(err_msg));
						break;
					case PB_ERROR_VERSION_NOT_SUPPORTED:
						DBG1(DBG_TNC, "received %s PB-TNC Error '%N' "
									  "caused by bad version 0x%02x",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code,
									  err_msg->get_bad_version(err_msg));
						break;
					case PB_ERROR_UNEXPECTED_BATCH_TYPE:
					case PB_ERROR_LOCAL_ERROR:
					default:
						DBG1(DBG_TNC, "received %s PB-TNC Error '%N'",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code);
						break;
				}
			}
			else
			{
				DBG1(DBG_TNC, "received %s PB-TNC Error (%u) "
							  "with Vendor ID 0x%06x",
							  fatal ? "fatal" : "non-fatal",
							  error_code, vendor_id);
			}
			break;
		}
		case PB_MSG_LANGUAGE_PREFERENCE:
		{
			pb_language_preference_message_t *lang_msg;
			chunk_t lang;

			lang_msg = (pb_language_preference_message_t*)msg;
			lang = lang_msg->get_language_preference(lang_msg);

			DBG2(DBG_TNC, "setting language preference '%.*s'", lang.len, lang.ptr);
			this->recs->set_preferred_language(this->recs, lang);
			break;
		}
		case PB_MSG_REASON_STRING:
		{
			pb_reason_string_message_t *reason_msg;
			chunk_t reason_string, language_code;

			reason_msg = (pb_reason_string_message_t*)msg;
			reason_string = reason_msg->get_reason_string(reason_msg);
			language_code = reason_msg->get_language_code(reason_msg);
			DBG2(DBG_TNC, "reason string: '%.*s", reason_string.len,
												  reason_string.ptr);
			DBG2(DBG_TNC, "language code: '%.*s", language_code.len,
												  language_code.ptr);
			break;
		}
		default:
			break;
	}
}

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	chunk_t data;
	pb_tnc_batch_t *batch;
	pb_tnc_message_t *msg;
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
	status = batch->process(batch, this->state_machine);

	if (status != FAILED)
	{
		enumerator_t *enumerator;
		pb_tnc_message_t *msg;
		pb_tnc_batch_type_t batch_type;
		bool empty = TRUE;

		batch_type = batch->get_type(batch);

		if (batch_type == PB_BATCH_CRETRY)
		{
			this->mutex->lock(this->mutex);
			if (this->batch)
			{
				DBG1(DBG_TNC, "cancelling PB-TNC %N Batch",
					pb_tnc_batch_type_names, this->batch->get_type(this->batch));
				this->batch->destroy(this->batch);
			 }
			this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_SRETRY);
			this->mutex->unlock(this->mutex);
		}
		else if (batch_type == PB_BATCH_SRETRY)
		{
			/* Restart the measurements */
			charon->imcs->notify_connection_change(charon->imcs,
			this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
			charon->imcs->begin_handshake(charon->imcs, this->connection_id);
		}

		enumerator = batch->create_msg_enumerator(batch);
		while (enumerator->enumerate(enumerator, &msg))
		{
			handle_message(this, msg);
			empty = FALSE;
		}
		enumerator->destroy(enumerator);

		/* received an empty CLOSE Batch from PB-TNC Client */
		if (this->is_server && batch_type == PB_BATCH_CLOSE && empty)
		{
			batch->destroy(batch);
			return SUCCESS;
		}

		if (this->is_server)
		{
			charon->imvs->batch_ending(charon->imvs, this->connection_id);
		}
		else
		{
			charon->imcs->batch_ending(charon->imcs, this->connection_id);
		}
	}

	switch (status)
	{
		case FAILED:
			this->mutex->lock(this->mutex);
			if (this->batch)
			{
				DBG1(DBG_TNC, "cancelling PB-TNC %N Batch",
					pb_tnc_batch_type_names, this->batch->get_type(this->batch));
				this->batch->destroy(this->batch);
			 }
			this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_CLOSE);
			this->mutex->unlock(this->mutex);
			/* fall through to add error messages to outbound batch */
		case VERIFY_ERROR:
			enumerator = batch->create_error_enumerator(batch);
			while (enumerator->enumerate(enumerator, &msg))
			{
				this->mutex->lock(this->mutex);
				this->batch->add_message(this->batch, msg->get_ref(msg));
				this->mutex->unlock(this->mutex);
			}
			enumerator->destroy(enumerator);
			break;
		case SUCCESS:
		default:
			break;
	}
	batch->destroy(batch);

	return NEED_MORE;
}

METHOD(tls_t, build, status_t,
	private_tnccs_20_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	status_t status;

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

	/* Do not allow any asynchronous IMCs or IMVs to add additional messages */
	this->mutex->lock(this->mutex);

	if (!this->batch)
	{
		pb_tnc_state_t state;

		state = this->state_machine->get_state(this->state_machine);

		if (this->is_server)
		{
			if (state == PB_STATE_SERVER_WORKING)
			{
				TNC_IMV_Action_Recommendation rec;
				TNC_IMV_Evaluation_Result eval;
				pb_tnc_message_t *msg;

				/* Is an overall recommendation available? */
				if (!this->recs->have_recommendation(this->recs, &rec, &eval))
				{
					charon->imvs->solicit_recommendation(charon->imvs,
														 this->connection_id);
				}
				if (this->recs->have_recommendation(this->recs, &rec, &eval))
				{
					this->batch = pb_tnc_batch_create(this->is_server,
													  PB_BATCH_RESULT);
					msg = pb_assessment_result_message_create(eval);
					this->batch->add_message(this->batch, msg);
					msg = pb_access_recommendation_message_create(rec);
					this->batch->add_message(this->batch, msg);
				}
			}
		}
		else
		{
			/**
			 * if the DECIDED state has been reached and no CRETRY is under way
			 * or if a CLOSE batch with error messages has been received,
			 * reply with an empty CLOSE batch.
			 */
			if (state == PB_STATE_DECIDED || state == PB_STATE_END)
			{
				this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_CLOSE);
			}
		}
	}

	if (this->batch)
	{
		pb_tnc_batch_type_t batch_type;
		chunk_t data;

		batch_type = this->batch->get_type(this->batch);

		if (this->state_machine->send_batch(this->state_machine, batch_type))
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
		else
		{
			DBG1(DBG_TNC, "cancelling unexpected PB-TNC Batch Type: %N",
				 pb_tnc_batch_type_names, batch_type);
			status = INVALID_STATE;
		}

		this->batch->destroy(this->batch);
		this->batch = NULL;
	}
	else
	{
		DBG1(DBG_TNC, "no TNCCS Batch to send");
		status = INVALID_STATE;
	}
	this->mutex->unlock(this->mutex);

	return status;
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
		DBG2(DBG_TNC, "Final recommendation is '%N' and evaluation is '%N'",
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
	this->state_machine->destroy(this->state_machine);
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
		.state_machine = pb_tnc_state_machine_create(is_server),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
