/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "pb_pdp_referral_msg.h"

#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/debug.h>

ENUM(pb_tnc_pdp_identifier_type_names, PB_PDP_ID_FQDN, PB_PDP_ID_IPV6,
	"PDP FQDN ID",
	"PDP IPv4 ID",
	"PDP IPv6 ID"
);

typedef struct private_pb_pdp_referral_msg_t private_pb_pdp_referral_msg_t;

/**
 *   PB-PDP-Referral message (see section 3.1.1.1 of
 *   TCG TNC PDP Discovery and Validation Specification 1.0
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Reserved    |           PDP Identifier Vendor ID            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      PDP Identifier Type                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 PDP Identifier (Variable Length)              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Section 3.1.1.2.1 FQDN Identifier
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Reserved    |   Protocol    |        Port Number            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                     FQDN (Variable Length)                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Section 3.1.1.2.2 IPv4 Identifier
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Reserved    |   Protocol    |        Port Number            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          IPv4 Address                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Section 3.1.1.2.3 IPv6 Identifier
 * 
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Reserved    |   Protocol    |        Port Number            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    IPv6 Address (octets 1-4)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    IPv6 Address (octets 5-8)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    IPv6 Address (octets 9-12)                 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    IPv6 Address (octets 13-16)                |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * Private data of a pb_pdp_referral_msg_t object.
 *
 */
struct private_pb_pdp_referral_msg_t {
	/**
	 * Public pb_pdp_referral_msg_t interface.
	 */
	pb_pdp_referral_msg_t public;

	/**
	 * PB-TNC message type
	 */
	pen_type_t type;

	/**
	 * PDP Identifier Type
	 */
	pen_type_t identifier_type;

	/**
	 * PDP Identifier Value
	 */
	chunk_t identifier;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pb_tnc_msg_t, get_type, pen_type_t,
	private_pb_pdp_referral_msg_t *this)
{
	return this->type;
}

METHOD(pb_tnc_msg_t, get_encoding, chunk_t,
	private_pb_pdp_referral_msg_t *this)
{
	return this->encoding;
}

METHOD(pb_tnc_msg_t, build, void,
	private_pb_pdp_referral_msg_t *this)
{
	bio_writer_t *writer;

	if (this->encoding.ptr)
	{
		return;
	}
	writer = bio_writer_create(64);
	writer->write_uint32(writer, this->identifier_type.vendor_id);
	writer->write_uint32(writer, this->identifier_type.type);
	writer->write_data(writer, this->identifier);

	this->encoding = writer->get_buf(writer);
	this->encoding = chunk_clone(this->encoding);
	writer->destroy(writer);
}

METHOD(pb_tnc_msg_t, process, status_t,
	private_pb_pdp_referral_msg_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int8_t reserved;
	status_t status = SUCCESS;

	*offset = 0;

	/* process message */
	reader = bio_reader_create(this->encoding);
	reader->read_uint8 (reader, &reserved);
	reader->read_uint24(reader, &this->identifier_type.vendor_id);
	reader->read_uint32(reader, &this->identifier_type.type);
	reader->read_data  (reader, reader->remaining(reader), &this->identifier);

	this->identifier = chunk_clone(this->identifier);
	reader->destroy(reader);

	if (this->identifier_type.vendor_id == PEN_TCG)
	{
		/* TODO parse PDP Identifier Types */
	}
	return status;
}

METHOD(pb_tnc_msg_t, destroy, void,
	private_pb_pdp_referral_msg_t *this)
{
	free(this->encoding.ptr);
	free(this->identifier.ptr);
	free(this);
}

METHOD(pb_pdp_referral_msg_t, get_identifier_type, pen_type_t,
	private_pb_pdp_referral_msg_t *this)
{
	return this->identifier_type;
}

METHOD(pb_pdp_referral_msg_t, get_identifier, chunk_t,
	private_pb_pdp_referral_msg_t *this)
{
	return this->identifier;
}

/**
 * See header
 */
pb_tnc_msg_t* pb_pdp_referral_msg_create(pen_type_t identifier_type,
										 chunk_t identifier)
{
	private_pb_pdp_referral_msg_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_identifier_type = _get_identifier_type,
			.get_identifier = _get_identifier,
		},
		.type = { PEN_TCG, PB_TCG_MSG_PDP_REFERRAL },
		.identifier_type = identifier_type,
		.identifier = chunk_clone(identifier),
	);

	return &this->public.pb_interface;
}

/**
 * See header
 */
pb_tnc_msg_t *pb_pdp_referral_msg_create_from_data(chunk_t data)
{
	private_pb_pdp_referral_msg_t *this;

	INIT(this,
		.public = {
			.pb_interface = {
				.get_type = _get_type,
				.get_encoding = _get_encoding,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_identifier_type = _get_identifier_type,
			.get_identifier = _get_identifier,
		},
		.type = { PEN_TCG, PB_TCG_MSG_PDP_REFERRAL },
		.encoding = chunk_clone(data),
	);

	return &this->public.pb_interface;
}

