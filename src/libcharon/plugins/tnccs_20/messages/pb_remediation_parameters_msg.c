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

#include "pb_remediation_parameters_msg.h"

#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

ENUM(pb_tnc_remed_param_type_names, PB_REMEDIATION_URI, PB_REMEDIATION_STRING,
	"Remediation-URI",
	"Remediation-String"
);

typedef struct private_pb_remediation_parameters_msg_t private_pb_remediation_parameters_msg_t;

/**
 *   PB-Remediation-Parameters message (see section 4.8 of RFC 5793)
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Reserved   |       Remediation Parameters Vendor ID        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                  Remediation Parameters Type                  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            Remediation Parameters (Variable Length)           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                   Remediation String Length                   |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                Remediation String (Variable Length)           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     | Lang Code Len |  Remediation String Lang Code (Variable Len)  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * Private data of a pb_remediation_parameters_msg_t object.
 *
 */
struct private_pb_remediation_parameters_msg_t {
	/**
	 * Public pb_remediation_parameters_msg_t interface.
	 */
	pb_remediation_parameters_msg_t public;

	/**
	 * PB-TNC message type
	 */
	pb_tnc_msg_type_t type;

	/**
	 * Remediation Parameters Vendor ID
	 */
	u_int32_t vendor_id;

	/**
	 * Remediation Parameters Type
	 */
	u_int32_t parameters_type;

	/**
	 * Remediation Parameters string
	 */
	chunk_t remediation_string;

	/**
	 * Language code
	 */
	chunk_t language_code;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pb_tnc_msg_t, get_type, pb_tnc_msg_type_t,
	private_pb_remediation_parameters_msg_t *this)
{
	return this->type;
}

METHOD(pb_tnc_msg_t, get_encoding, chunk_t,
	private_pb_remediation_parameters_msg_t *this)
{
	return this->encoding;
}

METHOD(pb_tnc_msg_t, build, void,
	private_pb_remediation_parameters_msg_t *this)
{
	bio_writer_t *writer;

	/* build message */
	writer = bio_writer_create(64);
	writer->write_uint32(writer, this->vendor_id);
	writer->write_uint32(writer, this->parameters_type);
	writer->write_data32(writer, this->remediation_string);
	writer->write_data8 (writer, this->language_code);

	free(this->encoding.ptr);
	this->encoding = writer->get_buf(writer);
	this->encoding = chunk_clone(this->encoding);
	writer->destroy(writer);
}

METHOD(pb_tnc_msg_t, process, status_t,
	private_pb_remediation_parameters_msg_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;

	/* process message */
	reader = bio_reader_create(this->encoding);
	reader->read_uint32(reader, &this->vendor_id);
	reader->read_uint32(reader, &this->parameters_type);

	if (!reader->read_data32(reader, &this->remediation_string))
	{
		DBG1(DBG_TNC, "could not parse remediation string");
		reader->destroy(reader);
		*offset = 8;
		return FAILED;
	};
	this->remediation_string = chunk_clone(this->remediation_string);

	if (this->remediation_string.len &&
		this->remediation_string.ptr[this->remediation_string.len-1] == '\0')
	{
		DBG1(DBG_TNC, "remediation string must not be null terminated");
		reader->destroy(reader);
		*offset = 11 + this->remediation_string.len;
		return FAILED;
	}

	if (!reader->read_data8(reader, &this->language_code))
	{
		DBG1(DBG_TNC, "could not parse language code");
		reader->destroy(reader);
		*offset = 12 + this->remediation_string.len;
		return FAILED;
	};
	this->language_code = chunk_clone(this->language_code);
	reader->destroy(reader);

	if (this->language_code.len &&
		this->language_code.ptr[this->language_code.len-1] == '\0')
	{
		DBG1(DBG_TNC, "language code must not be null terminated");
		*offset = 12 + this->remediation_string.len + this->language_code.len;
		return FAILED;
	}

	return SUCCESS;
}

METHOD(pb_tnc_msg_t, destroy, void,
	private_pb_remediation_parameters_msg_t *this)
{
	free(this->encoding.ptr);
	free(this->remediation_string.ptr);
	free(this->language_code.ptr);
	free(this);
}

METHOD(pb_remediation_parameters_msg_t, get_vendor_id, u_int32_t,
	private_pb_remediation_parameters_msg_t *this, u_int32_t *type)
{
	*type = this->parameters_type;
	return this->vendor_id;
}

METHOD(pb_remediation_parameters_msg_t, get_remediation_string, chunk_t,
	private_pb_remediation_parameters_msg_t *this)
{
	return this->remediation_string;
}

METHOD(pb_remediation_parameters_msg_t, get_language_code, chunk_t,
	private_pb_remediation_parameters_msg_t *this)
{
	return this->language_code;
}

/**
 * See header
 */
pb_tnc_msg_t *pb_remediation_parameters_msg_create_from_data(chunk_t data)
{
	private_pb_remediation_parameters_msg_t *this;

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
			.get_remediation_string = _get_remediation_string,
			.get_language_code = _get_language_code,
		},
		.type = PB_MSG_REASON_STRING,
		.encoding = chunk_clone(data),
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_msg_t* pb_remediation_parameters_msg_create(u_int32_t vendor_id,
												   u_int32_t type,
												   chunk_t remediation_string,
												   chunk_t language_code)
{
	private_pb_remediation_parameters_msg_t *this;

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
			.get_remediation_string = _get_remediation_string,
			.get_language_code = _get_language_code,
		},
		.type = PB_MSG_REASON_STRING,
		.vendor_id = vendor_id,
		.parameters_type = type,
		.remediation_string = chunk_clone(remediation_string),
		.language_code = chunk_clone(language_code),
	);

	return &this->public.pb_interface;
}
