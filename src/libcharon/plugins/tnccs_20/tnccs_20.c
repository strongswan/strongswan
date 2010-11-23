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
#include "tnccs_20_types.h"
#include "messages/pb_tnc_message.h"
#include "messages/pb_pa_message.h"

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
	 * Flag set by IMC/IMV RequestHandshakeRetry() function
	 */
	bool request_handshake_retry;

	/**
	 * Set of IMV recommendations  (TNC Server only)
	 */
	recommendations_t *recs;
};

/**
 *   PB-TNC Message (see section 4.2 of RFC 5793)
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |     Flags     |               PB-TNC Vendor ID                |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       PB-TNC Message Type                     |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      PB-TNC Message Length                    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |               PB-TNC Message Value (Variable Length)          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PB_TNC_HEADER_SIZE		12
#define PB_TNC_NOSKIP_FLAG		(1<<7)
#define PB_TNC_IETF_VENDOR_ID	0x000000

static chunk_t build_pb_tnc_msg(pb_tnc_msg_type_t msg_type, chunk_t msg_value)
{
	chunk_t msg, msg_header;
	tls_writer_t *writer;
	size_t msg_len;

	msg_len = PB_TNC_HEADER_SIZE + msg_value.len;
	writer = tls_writer_create(PB_TNC_HEADER_SIZE);
	writer->write_uint8 (writer, PB_TNC_NOSKIP_FLAG);
	writer->write_uint24(writer, PB_TNC_IETF_VENDOR_ID);
	writer->write_uint32(writer, msg_type);
	writer->write_uint32(writer, msg_len);
	msg_header = writer->get_buf(writer);
	msg = chunk_cat("cc", msg_header, msg_value);
	writer->destroy(writer);

	DBG2(DBG_TNC, "building %N message (%u bytes)", pb_tnc_msg_type_names,
													msg_type, msg_len);
	DBG3(DBG_TNC,"%B", &msg);

	return msg;
}

static status_t process_pb_tnc_msg(tls_reader_t *reader,
								   pb_tnc_message_t **pb_tnc_msg)
{
	u_int8_t flags;
	u_int32_t vendor_id, msg_type;
	size_t msg_len;
	chunk_t msg, msg_value;

	msg = reader->peek(reader);

	if (msg.len < PB_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PB-TNC message header",
					   msg.len);
		return FAILED;
	}
	reader->read_uint8 (reader, &flags);
	reader->read_uint24(reader, &vendor_id);
	reader->read_uint32(reader, &msg_type);
	reader->read_uint32(reader, &msg_len);

	DBG2(DBG_TNC, "processing PB-TNC message (%u bytes)", msg_len);

	if (msg_len < PB_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes too small for PB-TNC message length", msg_len);
		return FAILED;
	}
	if (msg_len > msg.len)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PB-TNC message", msg.len);
		return FAILED;
	}
	msg.len = msg_len;
	DBG3(DBG_TNC, "%B", &msg);
	reader->read_data(reader, msg_len - PB_TNC_HEADER_SIZE, &msg_value);

	if (vendor_id != PB_TNC_IETF_VENDOR_ID || msg_type > PB_MSG_ROOF)
	{
		if (flags & PB_TNC_NOSKIP_FLAG)
		{
			DBG1(DBG_TNC, "cannot process PB-TNC message with Vendor ID 0x%06x "
						  " and type 0x%08x", vendor_id, msg);
			return FAILED;
		}
		else
		{
			DBG1(DBG_TNC, "ignore PB-TNC message with Vendor ID 0x%06x "
						  " and type 0x%08x", vendor_id, msg);
			return INVALID_STATE;
		}
	}
	DBG2(DBG_TNC, "processing %N message (%u bytes)", pb_tnc_msg_type_names,
				   msg_type, msg_value.len);
	*pb_tnc_msg = pb_tnc_message_create(msg_type, msg_value);

	return SUCCESS;
}

METHOD(tnccs_t, send_message, void,
	private_tnccs_20_t* this, TNC_IMCID imc_id, TNC_IMVID imv_id,
							  TNC_BufferReference msg,
							  TNC_UInt32 msg_len,
							  TNC_MessageType msg_type)
{
	pb_tnc_message_t *pb_pa_msg;
	chunk_t pb_tnc_msg;
    TNC_MessageSubtype msg_sub_type;
    TNC_VendorID       msg_vendor_id;

	msg_sub_type =   msg_type       & TNC_SUBTYPE_ANY;
	msg_vendor_id = (msg_type >> 8) & TNC_VENDORID_ANY;

	pb_pa_msg = pb_pa_message_create(msg_vendor_id, msg_sub_type, imc_id, imv_id,
									 chunk_create(msg, msg_len));
	pb_pa_msg->build(pb_pa_msg);
	pb_tnc_msg = build_pb_tnc_msg(PB_MSG_PA, pb_pa_msg->get_encoding(pb_pa_msg));
	pb_pa_msg->destroy(pb_pa_msg);

	this->mutex->lock(this->mutex);
	this->batch = chunk_cat("mm", this->batch, pb_tnc_msg);
	this->mutex->unlock(this->mutex);
}

METHOD(tls_t, process, status_t,
	private_tnccs_20_t *this, void *buf, size_t buflen)
{
	tls_reader_t *reader;
	pb_tnc_message_t *msg = NULL;
	status_t status;
	char *pos;
	size_t len;

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

		/* Test reason enumerator */
		{
			chunk_t reason, reason_2 = { "virus alarm", 11 };
			chunk_t reason_lang, reason_lang_2 = { "en, ru", 6 };
			TNC_IMVID id;
			enumerator_t *enumerator;

			this->recs->set_reason_string(this->recs, 2, reason_2);
			this->recs->set_reason_language(this->recs, 2, reason_lang_2);

			enumerator = this->recs->create_reason_enumerator(this->recs);
			while (enumerator->enumerate(enumerator, &id, &reason, &reason_lang))
			{
				DBG1(DBG_TNC, "IMV %u: reason = '%.*s', lang = '%.*s'",
					 id, reason.len, reason.ptr, reason_lang.len, reason_lang.ptr);
			}
			enumerator->destroy(enumerator);
		}
	}
	DBG1(DBG_TNC, "received TNCCS Batch (%u bytes) for Connection ID %u",
				   buflen, this->connection_id);

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
	reader = tls_reader_create(chunk_create(pos, len));
	while (reader->remaining(reader) > 0)
	{
		switch (process_pb_tnc_msg(reader, &msg))
		{
			case SUCCESS:
				break;
			case INVALID_STATE:
				continue;
			default:
				reader->destroy(reader);
				return FAILED;
		}

		status = msg->process(msg);
		if (status != SUCCESS)
		{
			msg->destroy(msg);
			reader->destroy(reader);
			return status;
		}

		switch (msg->get_type(msg))
		{
			case PB_MSG_PA:
			{
				TNC_MessageType msg_type;
				u_int32_t vendor_id, subtype;
				chunk_t msg_body;
				pb_pa_message_t *pb_pa_msg;

				pb_pa_msg = (pb_pa_message_t*)msg;
				vendor_id = pb_pa_msg->get_vendor_id(pb_pa_msg, &subtype);
				msg_type = (vendor_id << 8) | subtype;
				msg_body = pb_pa_msg->get_body(pb_pa_msg);
				DBG2(DBG_TNC, "message type: 0x%08x", msg_type);
				if (this->is_server)
				{
					charon->imvs->receive_message(charon->imvs,
						 		this->connection_id, msg_body.ptr, msg_body.len,
								msg_type);
				}
				else
				{
					charon->imcs->receive_message(charon->imcs,
						 		this->connection_id, msg_body.ptr, msg_body.len,
								msg_type);
				}
				break;
			}
			case PB_MSG_ERROR:
				break;
			case PB_MSG_EXPERIMENTAL:
				break;
			case PB_MSG_LANGUAGE_PREFERENCE:
				break;
			case PB_MSG_ASSESSMENT_RESULT:
			case PB_MSG_ACCESS_RECOMMENDATION:
			case PB_MSG_REMEDIATION_PARAMETERS:
			case PB_MSG_REASON_STRING:
				break;
		}
		msg->destroy(msg);
	}
	reader->destroy(reader);

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
	char *msg = this->is_server ? "tncs->tncc 2.0|" : "tncc->tncs 2.0|";
	size_t len;

	this->mutex->lock(this->mutex);
	this->batch = chunk_cat("cm", chunk_create(msg, strlen(msg)), this->batch);
	this->mutex->unlock(this->mutex);

	if (!this->is_server && !this->connection_id)
	{
		this->connection_id = charon->tnccs->create_connection(charon->tnccs,
										(tnccs_t*)this, _send_message,
										&this->request_handshake_retry, NULL);
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
