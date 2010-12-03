/*
 * Copyright (C) 2010 Sansar Choinyambuu
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

#include "pb_error_message.h"
#include "../tnccs_20_types.h"

#include <tls_writer.h>
#include <tls_reader.h>
#include <debug.h>

typedef struct private_pb_error_message_t private_pb_error_message_t;

/**
 *   PB-Error message (see section 4.9 of RFC 5793)
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Flags      |              Error Code Vendor ID             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           Error Code          |           Reserved            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                Error Parameters (Variable Length)             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define ERROR_FLAG_NONE		0x00
#define ERROR_FLAG_FATAL	(1<<7)
#define ERROR_RESERVED	 	0x00
#define ERROR_HEADER_SIZE	8

/**
 * Private data of a pb_error_message_t object.
 *
 */
struct private_pb_error_message_t {
	/**
	 * Public pb_error_message_t interface.
	 */
	pb_error_message_t public;

	/**
	 * PB-TNC message type
	 */
	pb_tnc_msg_type_t type;

	/**
	 * Fatal flag
	 */
	bool fatal;

	/**
	 * PB Error Code Vendor ID
	 */
	u_int32_t vendor_id;

	/**
	 * PB Error Code
	 */
	u_int16_t error_code;

	/**
	 * PB Error Parameters
	 */
	u_int32_t error_parameters;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pb_tnc_message_t, get_type, pb_tnc_msg_type_t,
	private_pb_error_message_t *this)
{
	return this->type;
}

METHOD(pb_tnc_message_t, get_encoding, chunk_t,
	private_pb_error_message_t *this)
{
	return this->encoding;
}

METHOD(pb_tnc_message_t, build, void,
	private_pb_error_message_t *this)
{
	tls_writer_t *writer;

	/* build message header */
	writer = tls_writer_create(ERROR_HEADER_SIZE);
	writer->write_uint8 (writer, this->fatal ?
		ERROR_FLAG_FATAL : ERROR_FLAG_NONE);
	writer->write_uint24(writer, this->vendor_id);
	writer->write_uint16(writer, this->error_code);
	writer->write_uint16(writer, ERROR_RESERVED);

	/* create encoding by concatenating message header and message body */
	free(this->encoding.ptr);

	if(this->error_parameters)
	{
		if(this->error_code == PB_ERROR_VERSION_NOT_SUPPORTED)
		{
			/* Bad version */
			writer->write_uint8(writer, this->error_parameters);
			writer->write_uint8(writer, 2); /* Max version */
			writer->write_uint8(writer, 2); /* Min version */
			writer->write_uint8(writer, 0); /* Reserved */
		}
		else
		{
			/* Error parameters */
			writer->write_uint32(writer, this->error_parameters);
		}
	}
	this->encoding = writer->get_buf(writer);
	this->encoding = chunk_clone(this->encoding);
	writer->destroy(writer);
}

METHOD(pb_tnc_message_t, process, status_t,
	private_pb_error_message_t *this)
{
	u_int8_t flags;
	u_int16_t reserved;
	size_t error_parameters_len;
	tls_reader_t *reader;

	if (this->encoding.len < ERROR_HEADER_SIZE)
	{
		DBG1(DBG_TNC,"%N message is shorter than header size of %u bytes",
			 pb_tnc_msg_type_names, PB_MSG_ERROR, ERROR_HEADER_SIZE);
		return FAILED;
	}

	/* process message header */
	reader = tls_reader_create(this->encoding);
	reader->read_uint8 (reader, &flags);
	reader->read_uint24(reader, &this->vendor_id);
	reader->read_uint16(reader, &this->error_code);
	reader->read_uint16(reader, &reserved);

	/* process error parameters */
	error_parameters_len = reader->remaining(reader);
	if (error_parameters_len)
	{
		reader->read_uint32(reader, &this->error_parameters);
	}
	reader->destroy(reader);
	return SUCCESS;
}

METHOD(pb_tnc_message_t, destroy, void,
	private_pb_error_message_t *this)
{
	free(this->encoding.ptr);
	free(this);
}

METHOD(pb_error_message_t, get_vendor_id, u_int32_t,
	private_pb_error_message_t *this)
{
	return this->vendor_id;
}

METHOD(pb_error_message_t, get_error_code, u_int16_t,
	private_pb_error_message_t *this)
{
	return this->error_code;
}

METHOD(pb_error_message_t, get_parameters, u_int32_t,
	private_pb_error_message_t *this)
{
	return this->error_parameters;
}

METHOD(pb_error_message_t, get_fatal_flag, bool,
	private_pb_error_message_t *this)
{
	return this->fatal;
}

METHOD(pb_error_message_t, set_fatal_flag, void,
	private_pb_error_message_t *this, bool fatal)
{
	this->fatal = fatal;
}

/**
 * See header
 */
pb_tnc_message_t *pb_error_message_create_from_data(chunk_t data)
{
	private_pb_error_message_t *this;

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
			.get_error_code = _get_error_code,
			.get_parameters = _get_parameters,
			.get_fatal_flag = _get_fatal_flag,
			.set_fatal_flag = _set_fatal_flag,
		},
		.type = PB_MSG_ERROR,
		.encoding = chunk_clone(data),
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_message_t *pb_error_message_create(u_int32_t vendor_id,
						pb_tnc_error_code_t error_code)
{
	private_pb_error_message_t *this;

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
			.get_error_code = _get_error_code,
			.get_parameters = _get_parameters,
			.get_fatal_flag = _get_fatal_flag,
			.set_fatal_flag = _set_fatal_flag,
		},
		.type = PB_MSG_ERROR,
		.vendor_id = vendor_id,
		.error_code = error_code,
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_message_t *pb_error_message_create_with_parameter(u_int32_t vendor_id,
											pb_tnc_error_code_t error_code,
											u_int32_t error_parameters)
{
	private_pb_error_message_t *this;

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
			.get_error_code = _get_error_code,
			.get_parameters = _get_parameters,
			.get_fatal_flag = _get_fatal_flag,
			.set_fatal_flag = _set_fatal_flag,
		},
		.type = PB_MSG_ERROR,
		.vendor_id = vendor_id,
		.error_code = error_code,
		.error_parameters = error_parameters,
	);

	return &this->public.pb_interface;
}
