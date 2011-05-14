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
#include "batch/pb_tnc_batch.h"
#include "messages/pb_tnc_msg.h"
#include "messages/pb_pa_msg.h"
#include "messages/pb_error_msg.h"
#include "messages/pb_assessment_result_msg.h"
#include "messages/pb_access_recommendation_msg.h"
#include "messages/pb_remediation_parameters_msg.h"
#include "messages/pb_reason_string_msg.h"
#include "messages/pb_language_preference_msg.h"
#include "state_machine/pb_tnc_state_machine.h"

#include <debug.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <tnc/tncif.h>
#include <tnc/tncifimv.h>
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
	 * Flag set while processing
	 */
	bool fatal_error;

	/**
	 * Flag set by IMC/IMV RequestHandshakeRetry() function
	 */
	bool request_handshake_retry;

	/**
	  * SendMessage() by IMC/IMV only allowed if flag is set
	  */
	bool send_msg;

	/**
	 * Set of IMV recommendations  (TNC Server only)
	 */
	recommendations_t *recs;
};

METHOD(tnccs_t, send_msg, TNC_Result,
	private_tnccs_20_t* this, TNC_IMCID imc_id, TNC_IMVID imv_id,
							  TNC_BufferReference msg,
							  TNC_UInt32 msg_len,
							  TNC_MessageType msg_type)
{
	TNC_MessageSubtype msg_sub_type;
	TNC_VendorID msg_vendor_id;
	pb_tnc_msg_t *pb_tnc_msg;
	pb_tnc_batch_type_t batch_type;

	if (!this->send_msg)
	{
		DBG1(DBG_TNC, "%s %u not allowed to call SendMessage()",
			this->is_server ? "IMV" : "IMC",
			this->is_server ? imv_id : imc_id);
		return TNC_RESULT_ILLEGAL_OPERATION;
	}

	msg_sub_type =   msg_type       & TNC_SUBTYPE_ANY;
	msg_vendor_id = (msg_type >> 8) & TNC_VENDORID_ANY;

	pb_tnc_msg = pb_pa_msg_create(msg_vendor_id, msg_sub_type, imc_id, imv_id,
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
		this->batch->add_msg(this->batch, pb_tnc_msg);
	}
	else
	{
		pb_tnc_msg->destroy(pb_tnc_msg);
	}
	this->mutex->unlock(this->mutex);
	return TNC_RESULT_SUCCESS;
}

/**
 * Handle a single PB-TNC message according to its type
 */
static void handle_message(private_tnccs_20_t *this, pb_tnc_msg_t *msg)
{
	switch (msg->get_type(msg))
	{
		case PB_MSG_EXPERIMENTAL:
			/* nothing to do */
			break;
		case PB_MSG_PA:
		{
			pb_pa_msg_t *pa_msg;
			TNC_MessageType msg_type;
			u_int32_t vendor_id, subtype;
			chunk_t msg_body;

			pa_msg = (pb_pa_msg_t*)msg;
			vendor_id = pa_msg->get_vendor_id(pa_msg, &subtype);
			msg_type = (vendor_id << 8) | (subtype & 0xff);
			msg_body = pa_msg->get_body(pa_msg);

			DBG2(DBG_TNC, "handling PB-PA message type 0x%08x", msg_type);

			this->send_msg = TRUE;
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
			this->send_msg = FALSE;
			break;
		}
		case PB_MSG_ASSESSMENT_RESULT:
		{
			pb_assessment_result_msg_t *assess_msg;
			u_int32_t result;

			assess_msg = (pb_assessment_result_msg_t*)msg;
			result = assess_msg->get_assessment_result(assess_msg);
			DBG1(DBG_TNC, "PB-TNC assessment result is '%N'",
				 TNC_IMV_Evaluation_Result_names, result);
			break;
		}
		case PB_MSG_ACCESS_RECOMMENDATION:
		{
			pb_access_recommendation_msg_t *rec_msg;
			pb_access_recommendation_code_t rec;
			TNC_ConnectionState state = TNC_CONNECTION_STATE_ACCESS_NONE;

			rec_msg = (pb_access_recommendation_msg_t*)msg;
			rec = rec_msg->get_access_recommendation(rec_msg);
			DBG1(DBG_TNC, "PB-TNC access recommendation is '%N'",
						   pb_access_recommendation_code_names, rec);
			switch (rec)
			{
				case PB_REC_ACCESS_ALLOWED:
					state = TNC_CONNECTION_STATE_ACCESS_ALLOWED;
					break;
				case PB_REC_ACCESS_DENIED:
					state = TNC_CONNECTION_STATE_ACCESS_NONE;
					break;
				case PB_REC_QUARANTINED:
					state = TNC_CONNECTION_STATE_ACCESS_ISOLATED;
			}
			charon->imcs->notify_connection_change(charon->imcs,
												   this->connection_id, state);
			break;
		}
		case PB_MSG_REMEDIATION_PARAMETERS:
		{
			/* TODO : Remediation parameters message processing */
			break;
		}
		case PB_MSG_ERROR:
		{
			pb_error_msg_t *err_msg;
			bool fatal;
			u_int32_t vendor_id;
			u_int16_t error_code;

			err_msg = (pb_error_msg_t*)msg;
			fatal = err_msg->get_fatal_flag(err_msg);
			vendor_id = err_msg->get_vendor_id(err_msg);
			error_code = err_msg->get_error_code(err_msg);

			if (fatal)
			{
				this->fatal_error = TRUE;
			}

			if (vendor_id == IETF_VENDOR_ID)
			{
				switch (error_code)
				{
					case PB_ERROR_INVALID_PARAMETER:
					case PB_ERROR_UNSUPPORTED_MANDATORY_MSG:
						DBG1(DBG_TNC, "received %s PB-TNC error '%N' "
									  "(offset %u bytes)",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code,
									  err_msg->get_offset(err_msg));
						break;
					case PB_ERROR_VERSION_NOT_SUPPORTED:
						DBG1(DBG_TNC, "received %s PB-TNC error '%N' "
									  "caused by bad version 0x%02x",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code,
									  err_msg->get_bad_version(err_msg));
						break;
					case PB_ERROR_UNEXPECTED_BATCH_TYPE:
					case PB_ERROR_LOCAL_ERROR:
					default:
						DBG1(DBG_TNC, "received %s PB-TNC error '%N'",
									  fatal ? "fatal" : "non-fatal",
									  pb_tnc_error_code_names, error_code);
						break;
				}
			}
			else
			{
				DBG1(DBG_TNC, "received %s PB-TNC error (%u) "
							  "with Vendor ID 0x%06x",
							  fatal ? "fatal" : "non-fatal",
							  error_code, vendor_id);
			}
			break;
		}
		case PB_MSG_LANGUAGE_PREFERENCE:
		{
			pb_language_preference_msg_t *lang_msg;
			chunk_t lang;

			lang_msg = (pb_language_preference_msg_t*)msg;
			lang = lang_msg->get_language_preference(lang_msg);

			DBG2(DBG_TNC, "setting language preference to '%.*s'",
						   lang.len, lang.ptr);
			this->recs->set_preferred_language(this->recs, lang);
			break;
		}
		case PB_MSG_REASON_STRING:
		{
			pb_reason_string_msg_t *reason_msg;
			chunk_t reason_string, language_code;

			reason_msg = (pb_reason_string_msg_t*)msg;
			reason_string = reason_msg->get_reason_string(reason_msg);
			language_code = reason_msg->get_language_code(reason_msg);
			DBG2(DBG_TNC, "reason string is '%.*s", reason_string.len,
													reason_string.ptr);
			DBG2(DBG_TNC, "language code is '%.*s", language_code.len,
													language_code.ptr);
			break;
		}
		default:
			break;
	}
}

/**
 *  Build a CRETRY or SRETRY batch
 */
static void build_retry_batch(private_tnccs_20_t *this)
{
	pb_tnc_batch_type_t batch_retry_type;

	batch_retry_type = this->is_server ? PB_BATCH_SRETRY : PB_BATCH_CRETRY;
	if (this->batch)
	{
		if (this->batch->get_type(this->batch) == batch_retry_type)
		{
			/* retry batch has already been created */
			return;
		}
		DBG1(DBG_TNC, "cancelling PB-TNC %N batch",
			pb_tnc_batch_type_names, this->batch->get_type(this->batch));
		this->batch->destroy(this->batch);
	 }
	this->batch = pb_tnc_batch_create(this->is_server, batch_retry_type);
}

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	chunk_t data;
	pb_tnc_batch_t *batch;
	pb_tnc_msg_t *msg;
	enumerator_t *enumerator;
	status_t status;

	if (this->is_server && !this->connection_id)
	{
		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
								(tnccs_t*)this,	_send_msg,
								&this->request_handshake_retry, &this->recs);
		if (!this->connection_id)
		{
			return FAILED;
		}
		charon->imvs->notify_connection_change(charon->imvs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
		charon->imvs->notify_connection_change(charon->imvs,
							this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
	}

	data = chunk_create(buf, buflen);
	DBG1(DBG_TNC, "received TNCCS batch (%u bytes) for Connection ID %u",
				   data.len, this->connection_id);
	DBG3(DBG_TNC, "%B", &data);
	batch = pb_tnc_batch_create_from_data(this->is_server, data);
	status = batch->process(batch, this->state_machine);

	if (status != FAILED)
	{
		enumerator_t *enumerator;
		pb_tnc_msg_t *msg;
		pb_tnc_batch_type_t batch_type;
		bool empty = TRUE;

		batch_type = batch->get_type(batch);

		if (batch_type == PB_BATCH_CRETRY)
		{
			/* Send an SRETRY batch in response */
			this->mutex->lock(this->mutex);
			build_retry_batch(this);
			this->mutex->unlock(this->mutex);
		}
		else if (batch_type == PB_BATCH_SRETRY)
		{
			/* Restart the measurements */
			charon->imcs->notify_connection_change(charon->imcs,
			this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
			this->send_msg = TRUE;
			charon->imcs->begin_handshake(charon->imcs, this->connection_id);
			this->send_msg = FALSE;
		}

		enumerator = batch->create_msg_enumerator(batch);
		while (enumerator->enumerate(enumerator, &msg))
		{
			handle_message(this, msg);
			empty = FALSE;
		}
		enumerator->destroy(enumerator);

		/* received an empty CLOSE batch from PB-TNC client */
		if (this->is_server && batch_type == PB_BATCH_CLOSE && empty)
		{
			batch->destroy(batch);
			if (this->fatal_error)
			{
				DBG1(DBG_TNC, "a fatal PB-TNC error occurred, "
							  "terminating connection");
				return FAILED;
			}
			else
			{
				return SUCCESS;
			}
		}

		this->send_msg = TRUE;
		if (this->is_server)
		{
			charon->imvs->batch_ending(charon->imvs, this->connection_id);
		}
		else
		{
			charon->imcs->batch_ending(charon->imcs, this->connection_id);
		}
		this->send_msg = FALSE;
	}

	switch (status)
	{
		case FAILED:
			this->fatal_error = TRUE;
			this->mutex->lock(this->mutex);
			if (this->batch)
			{
				DBG1(DBG_TNC, "cancelling PB-TNC %N batch",
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
				this->batch->add_msg(this->batch, msg->get_ref(msg));
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

/**
 *  Build a RESULT batch if a final recommendation is available
 */
static void check_and_build_recommendation(private_tnccs_20_t *this)
{
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	TNC_IMVID id;
	chunk_t reason, language;
	enumerator_t *enumerator;
	pb_tnc_msg_t *msg;

	if (!this->recs->have_recommendation(this->recs, &rec, &eval))
	{
		charon->imvs->solicit_recommendation(charon->imvs, this->connection_id);
	}
	if (this->recs->have_recommendation(this->recs, &rec, &eval))
	{
		this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_RESULT);

		msg = pb_assessment_result_msg_create(eval);
		this->batch->add_msg(this->batch, msg);

		/**
		 * IMV Action Recommendation and PB Access Recommendation codes
		 * are shifted by one.
		 */
		msg = pb_access_recommendation_msg_create(rec + 1);
		this->batch->add_msg(this->batch, msg);

		enumerator = this->recs->create_reason_enumerator(this->recs);
		while (enumerator->enumerate(enumerator, &id, &reason, &language))
		{
			msg = pb_reason_string_msg_create(reason, language);
			this->batch->add_msg(this->batch, msg);
		}
		enumerator->destroy(enumerator);
	}
}

METHOD(tls_t, build, status_t,
	private_tnccs_20_t *this, void *buf, size_t *buflen, size_t *msglen)
{
	status_t status;
	pb_tnc_state_t state;

	/* Initialize the connection */
	if (!this->is_server && !this->connection_id)
	{
		pb_tnc_msg_t *msg;
		char *pref_lang;

		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
										(tnccs_t*)this, _send_msg,
										&this->request_handshake_retry, NULL);
		if (!this->connection_id)
		{
			return FAILED;
		}

		/* Create PB-TNC Language Preference message */
		pref_lang = charon->imcs->get_preferred_language(charon->imcs);
		msg = pb_language_preference_msg_create(chunk_create(pref_lang,
													strlen(pref_lang)));
		this->mutex->lock(this->mutex);
		this->batch = pb_tnc_batch_create(this->is_server, PB_BATCH_CDATA);
		this->batch->add_msg(this->batch, msg);
		this->mutex->unlock(this->mutex);

		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_CREATE);
		charon->imcs->notify_connection_change(charon->imcs,
							this->connection_id, TNC_CONNECTION_STATE_HANDSHAKE);
		this->send_msg = TRUE;
		charon->imcs->begin_handshake(charon->imcs, this->connection_id);
		this->send_msg = FALSE;
	}

	state = this->state_machine->get_state(this->state_machine);

	if (this->is_server && this->fatal_error && state == PB_STATE_END)
	{
		DBG1(DBG_TNC, "a fatal PB-TNC error occurred, terminating connection");
		return FAILED;
	}

	/* Do not allow any asynchronous IMCs or IMVs to add additional messages */
	this->mutex->lock(this->mutex);

	if (this->request_handshake_retry)
	{
		if (state != PB_STATE_INIT)
		{
			build_retry_batch(this);
		}

		/* Reset the flag for the next handshake retry request */
		this->request_handshake_retry = FALSE;
	}

	if (!this->batch)
	{
		if (this->is_server)
		{
			if (state == PB_STATE_SERVER_WORKING)
			{
				check_and_build_recommendation(this);
			}
		}
		else
		{
			/**
			 * if the DECIDED state has been reached and no CRETRY is under way
			 * or if a CLOSE batch with error messages has been received,
			 * a PB-TNC client replies with an empty CLOSE batch.
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
			DBG1(DBG_TNC, "sending PB-TNC %N batch (%d bytes) for Connection ID %u",
						   pb_tnc_batch_type_names, batch_type, data.len,
						   this->connection_id);
			DBG3(DBG_TNC, "%B", &data);
			*msglen = data.len;

			if (data.len > *buflen)
			{
				DBG1(DBG_TNC, "fragmentation of PB-TNC batch not supported yet");
			}
			else
			{
				*buflen = data.len;
			}
			memcpy(buf, data.ptr, *buflen);
			status = ALREADY_DONE;
		}
		else
		{
			DBG1(DBG_TNC, "cancelling unexpected PB-TNC batch type: %N",
				 pb_tnc_batch_type_names, batch_type);
			status = INVALID_STATE;
		}

		this->batch->destroy(this->batch);
		this->batch = NULL;
	}
	else
	{
		DBG1(DBG_TNC, "no PB-TNC batch to send");
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
		return charon->imvs->enforce_recommendation(charon->imvs, rec, eval);
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
	charon->tnccs->remove_connection(charon->tnccs, this->connection_id,
													this->is_server);
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
