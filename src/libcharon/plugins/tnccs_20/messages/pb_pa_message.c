/*
 * Copyright (C) 2010 Sansar Choinyanbuu
 * Copyright (C) 2010 Andreas Steffen
 *
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

#include "pb_pa_message.h"

#include <tls_writer.h>
#include <tls_reader.h>
#include <debug.h>

typedef struct private_pb_pa_message_t private_pb_pa_message_t;

/**
 *   PB-PA message
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Flags      |               PA Message Vendor ID            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                           PA Subtype                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  Posture Collector Identifier | Posture Validator Identifier  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                 PA Message Body (Variable Length)             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PA_FLAG_NONE	 0x00
#define PA_FLAG_EXCL	(1<<7)

#define PB_PA_HEADER_SIZE	12

/**
 * Private data of a pb_pa_message_t object.
 *
 */
struct private_pb_pa_message_t {
	/**
	 * Public pb_pa_message_t interface.
	 */
	pb_pa_message_t public;

	/**
	 * PB-TNC message type
	 */
	pb_tnc_msg_type_t type;

	/**
	 * Exclusive flag
	 */
	bool excl;

	/**
	 * PA Message Vendor ID
	 */
	u_int32_t vendor_id;

	/**
	 * PA Subtype
	 */
	u_int32_t subtype;

	/**
	 * Posture Validator Identifier
	 */
	u_int16_t collector_id;

	/**
	 * Posture Validator Identifier
	 */
	u_int16_t validator_id;

	/**
	 * PA Message Body
	 */
	chunk_t msg_body;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pb_tnc_message_t, get_type, pb_tnc_msg_type_t,
	private_pb_pa_message_t *this)
{
	return this->type;
}

METHOD(pb_tnc_message_t, get_encoding, chunk_t,
	private_pb_pa_message_t *this)
{
	return this->encoding;
}
	
METHOD(pb_tnc_message_t, build, void,
	private_pb_pa_message_t *this)
{
	chunk_t msg_header;
	tls_writer_t *writer;

	/* build message header */
	writer = tls_writer_create(PB_PA_HEADER_SIZE);
	writer->write_uint8 (writer, this->excl ? PA_FLAG_EXCL : PA_FLAG_NONE);
	writer->write_uint24(writer, this->vendor_id);
	writer->write_uint32(writer, this->subtype);
	writer->write_uint16(writer, this->collector_id);
	writer->write_uint16(writer, this->validator_id);
	msg_header = writer->get_buf(writer);

	/* create encoding by concatenating message header and message body */
	free(this->encoding.ptr);
	this->encoding = chunk_cat("cc", msg_header, this->msg_body);
	writer->destroy(writer);
}

METHOD(pb_tnc_message_t, process, status_t,
	private_pb_pa_message_t *this)
{
	u_int8_t flags;
	size_t msg_body_len;
	tls_reader_t *reader;

	if (this->encoding.len < PB_PA_HEADER_SIZE)
	{
		DBG1(DBG_TNC,"%N message is shorter than header size of %u bytes",
			 pb_tnc_msg_type_names, PB_MSG_PA, PB_PA_HEADER_SIZE);
		return FAILED;	
	}

	/* process message header */
	reader = tls_reader_create(this->encoding);
	reader->read_uint8 (reader, &flags);
	reader->read_uint24(reader, &this->vendor_id);
	reader->read_uint32(reader, &this->subtype);
	reader->read_uint16(reader, &this->collector_id);
	reader->read_uint16(reader, &this->validator_id);
	this->excl = ((flags & PA_FLAG_EXCL) != PA_FLAG_NONE);

	/* process message body */
	msg_body_len = reader->remaining(reader);
	if (msg_body_len)
	{
		reader->read_data(reader, msg_body_len, &this->msg_body);
		this->msg_body = chunk_clone(this->msg_body);
	}
	reader->destroy(reader);
	return SUCCESS;
}

METHOD(pb_tnc_message_t, destroy, void,
	private_pb_pa_message_t *this)
{
	free(this->encoding.ptr);
	free(this->msg_body.ptr);
	free(this);
}

METHOD(pb_pa_message_t, get_vendor_id, u_int32_t,
	private_pb_pa_message_t *this, u_int32_t *subtype)
{
	*subtype = this->subtype;
	return this->vendor_id;
}

METHOD(pb_pa_message_t, get_collector_id, u_int16_t,
	private_pb_pa_message_t *this)
{
	return this->collector_id;
}

METHOD(pb_pa_message_t, get_validator_id, u_int16_t,
	private_pb_pa_message_t *this)
{
	return this->validator_id;
}

METHOD(pb_pa_message_t, get_body, chunk_t,
	private_pb_pa_message_t *this)
{
	return this->msg_body;
}

METHOD(pb_pa_message_t, get_exclusive_flag, bool,
	private_pb_pa_message_t *this)
{
	return this->excl;
}

METHOD(pb_pa_message_t, set_exclusive_flag, void,
	private_pb_pa_message_t *this, bool excl)
{
	this->excl = excl;
}

/**
 * See header
 */
pb_tnc_message_t *pb_pa_message_create_from_data(chunk_t data)
{
	private_pb_pa_message_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.process = _process,
				.destroy = _destroy,
			},
			.get_vendor_id = _get_vendor_id,
			.get_collector_id = _get_collector_id,
			.get_validator_id = _get_validator_id,
			.get_body = _get_body,
			.get_exclusive_flag = _get_exclusive_flag,
			.set_exclusive_flag = _set_exclusive_flag,
		},
		.type = PB_MSG_PA,
		.encoding = chunk_clone(data),
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_message_t *pb_pa_message_create(u_int32_t vendor_id, u_int32_t subtype,
									   u_int16_t collector_id,
									   u_int16_t validator_id,
									   chunk_t msg_body)
{
	private_pb_pa_message_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_vendor_id = _get_vendor_id,
			.get_collector_id = _get_collector_id,
			.get_validator_id = _get_validator_id,
			.get_body = _get_body,
			.get_exclusive_flag = _get_exclusive_flag,
			.set_exclusive_flag = _set_exclusive_flag,
		},
		.type = PB_MSG_PA,
		.vendor_id = vendor_id,
		.subtype = subtype,
		.collector_id = collector_id,
		.validator_id = validator_id,
		.msg_body = chunk_clone(msg_body),
	);

	return &this->public.pb_interface;
}
