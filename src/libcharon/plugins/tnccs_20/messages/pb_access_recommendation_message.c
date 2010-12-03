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

#include "pb_access_recommendation_message.h"

#include <tls_writer.h>
#include <tls_reader.h>
#include <debug.h>

typedef struct private_pb_access_recommendation_message_t private_pb_access_recommendation_message_t;

/**
 *   PB-Access-Recommendation message (see section 4.7 of RFC 5793)
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |          Reserved             |   Access Recommendation Code  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define ACCESS_RECOMMENDATION_RESERVED	 	0x0000
#define ACCESS_RECOMMENDATION_MESSAGE_SIZE	4

/**
 * Private data of a private_pb_access_recommendation_message_t object.
 *
 */
struct private_pb_access_recommendation_message_t {
	/**
	 * Public pb_access_recommendation_message_t interface.
	 */
	pb_access_recommendation_message_t public;

	/**
	 * PB-TNC message type
	 */
	pb_tnc_msg_type_t type;
	
	/**
	 * Access recommendation code
	 */
	u_int16_t recommendation;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pb_tnc_message_t, get_type, pb_tnc_msg_type_t,
	private_pb_access_recommendation_message_t *this)
{
	return this->type;
}

METHOD(pb_tnc_message_t, get_encoding, chunk_t,
	private_pb_access_recommendation_message_t *this)
{
	return this->encoding;
}
	
METHOD(pb_tnc_message_t, build, void,
	private_pb_access_recommendation_message_t *this)
{
	tls_writer_t *writer;

	/* build message */
	writer = tls_writer_create(ACCESS_RECOMMENDATION_MESSAGE_SIZE);
	writer->write_uint16(writer, ACCESS_RECOMMENDATION_RESERVED);
	writer->write_uint16(writer, this->recommendation);
	free(this->encoding.ptr);
	this->encoding = writer->get_buf(writer);
	this->encoding = chunk_clone(this->encoding);
	writer->destroy(writer);
}

METHOD(pb_tnc_message_t, process, status_t,
	private_pb_access_recommendation_message_t *this)
{
	tls_reader_t *reader;
	u_int16_t reserved;

	if (this->encoding.len < ACCESS_RECOMMENDATION_MESSAGE_SIZE)
	{
		DBG1(DBG_TNC,"%N message is shorter than message size of %u bytes",
				pb_tnc_msg_type_names, PB_MSG_ACCESS_RECOMMENDATION, 
				ACCESS_RECOMMENDATION_MESSAGE_SIZE);
		return FAILED;	
	}

	/* process message */
	reader = tls_reader_create(this->encoding);
	reader->read_uint16(reader, &reserved);
	reader->read_uint16(reader, &this->recommendation);

	reader->destroy(reader);
	return SUCCESS;
}

METHOD(pb_tnc_message_t, destroy, void,
	private_pb_access_recommendation_message_t *this)
{
	free(this->encoding.ptr);
	free(this);
}

METHOD(pb_access_recommendation_message_t, get_access_recommendation, u_int16_t,
	private_pb_access_recommendation_message_t *this)
{
	return this->recommendation;
}

/**
 * See header
 */
pb_tnc_message_t *pb_access_recommendation_message_create_from_data(chunk_t data)
{
	private_pb_access_recommendation_message_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_access_recommendation = _get_access_recommendation,
		},
		.type = PB_MSG_ACCESS_RECOMMENDATION,
		.encoding = chunk_clone(data),
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_message_t *pb_access_recommendation_message_create(u_int16_t recommendation)
{
	private_pb_access_recommendation_message_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_access_recommendation = _get_access_recommendation,
		},
		.type = PB_MSG_ACCESS_RECOMMENDATION,
		.recommendation = recommendation,
	);

	return &this->public.pb_interface;
}
