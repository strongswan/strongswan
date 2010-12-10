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

#include "tnccs_20_types.h"
#include "pb_tnc_batch.h"
#include "messages/pb_error_message.h"
#include "state_machine/pb_tnc_state_machine.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <tls_writer.h>
#include <tls_reader.h>
#include <tnc/tnccs/tnccs.h>

ENUM(pb_tnc_batch_type_names, PB_BATCH_CDATA, PB_BATCH_CLOSE,
	"CDATA",
	"SDATA",
	"RESULT",
	"CRETRY",
	"SRETRY",
	"CLOSE"
);

typedef struct private_pb_tnc_batch_t private_pb_tnc_batch_t;

/**
 *   PB-Batch Header (see section 4.1 of RFC 5793)
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Version    |D|     Reserved                        | B-Type|
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       Batch Length                            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PB_TNC_BATCH_FLAG_NONE		0x00
#define PB_TNC_BATCH_FLAG_D			(1<<7)
#define PB_TNC_BATCH_HEADER_SIZE	8

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

#define PB_TNC_FLAG_NONE			0x00
#define PB_TNC_FLAG_NOSKIP			(1<<7)
#define PB_TNC_HEADER_SIZE			12

#define PB_TNC_RESERVED_MSG_TYPE	0xffffffff

/**
 * Private data of a pb_tnc_batch_t object.
 *
 */
struct private_pb_tnc_batch_t {
	/**
	 * Public pb_pa_message_t interface.
	 */
	pb_tnc_batch_t public;

	/**
	 * TNCC if TRUE, TNCS if FALSE
	 */
	bool is_server;

	/**
	 * PB-TNC Batch type
	 */
	pb_tnc_batch_type_t type;

	/**
	 * linked list of PB-TNC messages
	 */
	linked_list_t *messages;

	/**
	 * linked list of PB-TNC error messages
	 */
	linked_list_t *errors;

	/**
	 * Encoded message
	 */
	chunk_t encoding;

	/**
	 * Offset into encoding (used for error reporting)
	 */
	size_t offset;
};

METHOD(pb_tnc_batch_t, get_type, pb_tnc_batch_type_t,
	private_pb_tnc_batch_t *this)
{
	return this->type;
}

METHOD(pb_tnc_batch_t, get_encoding, chunk_t,
	private_pb_tnc_batch_t *this)
{
	return this->encoding;
}

METHOD(pb_tnc_batch_t, add_message, void,
	private_pb_tnc_batch_t *this, pb_tnc_message_t* msg)
{
	DBG2(DBG_TNC, "adding %N Message", pb_tnc_msg_type_names,
									   msg->get_type(msg));
	this->messages->insert_last(this->messages, msg);
}

METHOD(pb_tnc_batch_t, build, void,
	private_pb_tnc_batch_t *this)
{
	u_int32_t batch_len, msg_len;
	u_int8_t flags = PB_TNC_FLAG_NONE;
	chunk_t msg_value;
	enumerator_t *enumerator;
	pb_tnc_msg_type_t msg_type;
	pb_tnc_message_t *msg;
	tls_writer_t *writer;

	/* compute total PB-TNC batch size by summing over all messages */
	batch_len = PB_TNC_BATCH_HEADER_SIZE;
	enumerator = this->messages->create_enumerator(this->messages);
	while (enumerator->enumerate(enumerator, &msg))
	{
		msg->build(msg);
		msg_value = msg->get_encoding(msg);
		batch_len += PB_TNC_HEADER_SIZE + msg_value.len;
	}
	enumerator->destroy(enumerator);

	/* build PB-TNC batch header */
	writer = tls_writer_create(batch_len);	
	writer->write_uint8 (writer, PB_TNC_VERSION);
	writer->write_uint8 (writer, this->is_server ?
								 PB_TNC_BATCH_FLAG_D : PB_TNC_BATCH_FLAG_NONE);
	writer->write_uint16(writer, this->type);
	writer->write_uint32(writer, batch_len); 

	/* build PB-TNC messages */
	enumerator = this->messages->create_enumerator(this->messages);
	while (enumerator->enumerate(enumerator, &msg))
	{
		/* build PB-TNC message */
		msg_value = msg->get_encoding(msg);
		msg_len = PB_TNC_HEADER_SIZE + msg_value.len;
		msg_type = msg->get_type(msg);
		switch (msg_type)
		{
			case PB_MSG_PA:
			case PB_MSG_ASSESSMENT_RESULT:
			case PB_MSG_ERROR:
				flags |= PB_TNC_FLAG_NOSKIP;
				break;
			case PB_MSG_EXPERIMENTAL:
			case PB_MSG_ACCESS_RECOMMENDATION:
			case PB_MSG_REMEDIATION_PARAMETERS:
			case PB_MSG_LANGUAGE_PREFERENCE:
			case PB_MSG_REASON_STRING:
				break;
		}	
		writer->write_uint8 (writer, flags);
		writer->write_uint24(writer, IETF_VENDOR_ID);
		writer->write_uint32(writer, msg_type);
		writer->write_uint32(writer, msg_len);
		writer->write_data  (writer, msg_value);
	}
	enumerator->destroy(enumerator);

	this->encoding = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

static status_t process_batch_header(private_pb_tnc_batch_t *this,
									 pb_tnc_state_machine_t *state_machine)
{
	tls_reader_t *reader;
	pb_tnc_message_t *msg;
	pb_error_message_t *err_msg;
	u_int8_t version, flags, reserved, type;
	u_int32_t batch_len;
	bool directionality;

	if (this->encoding.len < PB_TNC_BATCH_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PB-TNC batch header",
					   this->encoding.len);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, 0);
		goto fatal;
	}

	reader = tls_reader_create(this->encoding);
	reader->read_uint8 (reader, &version);
	reader->read_uint8 (reader, &flags);
	reader->read_uint8 (reader, &reserved);
	reader->read_uint8 (reader, &type);
	reader->read_uint32(reader, &batch_len);
	reader->destroy(reader);

	/* Version */
	if (version != PB_TNC_VERSION)
	{
		DBG1(DBG_TNC, "unsupported TNCCS Batch Version 0x%01x", version);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_VERSION_NOT_SUPPORTED);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_bad_version(err_msg, version);
		goto fatal;
	}

	/* Directionality */
	directionality = (flags & PB_TNC_BATCH_FLAG_D) != PB_TNC_BATCH_FLAG_NONE;
	if (directionality == this->is_server)
	{
		DBG1(DBG_TNC, "wrong Directionality: Batch is from a PB %s",
			 directionality ? "Server" : "Client");
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, 1);
		goto fatal;
	}

	/* Batch Type */
	this->type = type & 0x0F;
	if (this->type > PB_BATCH_ROOF)
	{
		DBG1(DBG_TNC, "unknown PB-TNC Batch Type: %d", this->type);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, 3);
		goto fatal;
	}

	if (!state_machine->receive_batch(state_machine, this->type))
	{
		DBG1(DBG_TNC, "unexpected PB-TNC Batch Type: %N",
					   pb_tnc_batch_type_names, this->type);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_UNEXPECTED_BATCH_TYPE);
		goto fatal;
	}

	/* Batch Length */
	if (this->encoding.len != batch_len)
	{
		DBG1(DBG_TNC, "%u bytes of data is not equal to batch length of %u bytes",
					   this->encoding.len, batch_len);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, 4);
		goto fatal;
	}

	this->offset = PB_TNC_BATCH_HEADER_SIZE;
	return SUCCESS;

fatal:
	this->errors->insert_last(this->errors, msg);
	return FAILED;	
}

static status_t process_tnc_message(private_pb_tnc_batch_t *this)
{
	tls_reader_t *reader;
	pb_tnc_message_t *pb_tnc_msg, *msg;
	pb_error_message_t *err_msg;
	u_int8_t flags;
	u_int32_t vendor_id, msg_type, msg_len;
	chunk_t data, msg_value;
	status_t status;

	data = chunk_skip(this->encoding, this->offset);

	if (data.len < PB_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PB-TNC message header",
					  data.len);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, this->offset);
		goto fatal;
	}

	reader = tls_reader_create(data);
	reader->read_uint8 (reader, &flags);
	reader->read_uint24(reader, &vendor_id);
	reader->read_uint32(reader, &msg_type);
	reader->read_uint32(reader, &msg_len);
	reader->destroy(reader);

	if (msg_len < PB_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes too small for PB-TNC message length", msg_len);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, this->offset + 8);
		goto fatal;
	}

	if (msg_len > data.len)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PB-TNC message", data.len);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, this->offset + 8);
		goto fatal;
	}

	if (vendor_id == RESERVED_VENDOR_ID)
	{
		DBG1(DBG_TNC, "Vendor ID 0x%06x is reserved", RESERVED_VENDOR_ID);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, this->offset + 1);
		goto fatal;

	}

	if (msg_type == PB_TNC_RESERVED_MSG_TYPE)
	{
		DBG1(DBG_TNC, "PB-TNC Message Type 0x%08x is reserved",
			 PB_TNC_RESERVED_MSG_TYPE);
		msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									  PB_ERROR_INVALID_PARAMETER);
		err_msg = (pb_error_message_t*)msg;
		err_msg->set_offset(err_msg, this->offset + 4);
		goto fatal;
	}

	if (vendor_id != IETF_VENDOR_ID || msg_type > PB_MSG_ROOF)
	{
		if (flags & PB_TNC_FLAG_NOSKIP)
		{
			DBG1(DBG_TNC, "reject PB-TNC Message (Vendor ID 0x%06x / "
						  "Type 0x%08x)", vendor_id, msg_type);
			msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
									PB_ERROR_UNSUPPORTED_MANDATORY_MESSAGE);
			err_msg = (pb_error_message_t*)msg;
			err_msg->set_offset(err_msg, this->offset);
			goto fatal;
		}
		else
		{
			DBG1(DBG_TNC, "ignore PB-TNC Message (Vendor ID 0x%06x / "
						  "Type 0x%08x)", vendor_id, msg_type);
			this->offset += msg_len;
			return SUCCESS;
		}
	}

	if ((msg_type == PB_MSG_ASSESSMENT_RESULT ||
		 msg_type == PB_MSG_ACCESS_RECOMMENDATION ||
		 msg_type == PB_MSG_REMEDIATION_PARAMETERS) &&
		 this->type != PB_BATCH_RESULT)
	{
		if (this->is_server)
		{
			DBG1(DBG_TNC,"reject %N Message received from a PB-TNC Client",
						  pb_tnc_msg_type_names, msg_type);
			msg = pb_error_message_create(TRUE, IETF_VENDOR_ID,
										  PB_ERROR_INVALID_PARAMETER);
			err_msg = (pb_error_message_t*)msg;
			err_msg->set_offset(err_msg, this->offset);
			goto fatal;
		}
		else
		{
			DBG1(DBG_TNC,"ignore %N Message not received within RESULT batch",
						  pb_tnc_msg_type_names, msg_type);
			this->offset += msg_len;
			return SUCCESS;
		}
	}

	DBG2(DBG_TNC, "processing %N Message (%u bytes)", pb_tnc_msg_type_names,
				   msg_type, msg_len);
	data.len = msg_len;
	DBG3(DBG_TNC, "%B", &data);
	msg_value = chunk_skip(data, PB_TNC_HEADER_SIZE);
	pb_tnc_msg = pb_tnc_message_create(msg_type, msg_value);

	status = pb_tnc_msg->process(pb_tnc_msg);
	if (status == FAILED)
	{
		pb_tnc_msg->destroy(pb_tnc_msg);
		return FAILED;
	}
	this->messages->insert_last(this->messages, pb_tnc_msg);
	this->offset += msg_len;
	return SUCCESS;

fatal:
	this->errors->insert_last(this->errors, msg);
	return FAILED;	
}

METHOD(pb_tnc_batch_t, process, status_t,
	private_pb_tnc_batch_t *this, pb_tnc_state_machine_t *state_machine)
{
	status_t status;

	status = process_batch_header(this, state_machine);
	if (status != SUCCESS)
	{
		return FAILED;
	}
	DBG1(DBG_TNC, "processing PB-TNC %N Batch", pb_tnc_batch_type_names,
												this->type);
	while (this->offset < this->encoding.len)
	{
		switch (process_tnc_message(this))
		{
			case FAILED:
				return FAILED;
			case VERIFY_ERROR:
				status = VERIFY_ERROR;
				break;
			case SUCCESS:
			default:
				break;
		}
	}
	return status;
}

METHOD(pb_tnc_batch_t, create_msg_enumerator, enumerator_t*,
	private_pb_tnc_batch_t *this)
{
	return this->messages->create_enumerator(this->messages);
}

METHOD(pb_tnc_batch_t, create_error_enumerator, enumerator_t*,
	private_pb_tnc_batch_t *this)
{
	return this->errors->create_enumerator(this->errors);
}

METHOD(pb_tnc_batch_t, destroy, void,
	private_pb_tnc_batch_t *this)
{
	this->messages->destroy_offset(this->messages,
								   offsetof(pb_tnc_message_t, destroy));
	this->errors->destroy_offset(this->errors,
								   offsetof(pb_tnc_message_t, destroy));
	free(this->encoding.ptr);
	free(this);
}

/**
 * See header
 */
pb_tnc_batch_t* pb_tnc_batch_create(bool is_server, pb_tnc_batch_type_t type)
{
	private_pb_tnc_batch_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.get_encoding = _get_encoding,
			.add_message = _add_message,
			.build = _build,
			.process = _process,
			.create_msg_enumerator = _create_msg_enumerator,
			.create_error_enumerator = _create_error_enumerator,
			.destroy = _destroy,
		},
		.is_server = is_server,
		.type = type,
		.messages = linked_list_create(),
		.errors = linked_list_create(),
	);

	DBG2(DBG_TNC, "creating PB-TNC %N Batch", pb_tnc_batch_type_names, type);

	return &this->public;
}

/**
 * See header
 */
pb_tnc_batch_t* pb_tnc_batch_create_from_data(bool is_server, chunk_t data)
{
	private_pb_tnc_batch_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.get_encoding = _get_encoding,
			.add_message = _add_message,
			.build = _build,
			.process = _process,
			.create_msg_enumerator = _create_msg_enumerator,
			.create_error_enumerator = _create_error_enumerator,
			.destroy = _destroy,
		},
		.is_server = is_server,
		.messages = linked_list_create(),
		.errors = linked_list_create(),
		.encoding = chunk_clone(data),
	);

	return &this->public;
}

