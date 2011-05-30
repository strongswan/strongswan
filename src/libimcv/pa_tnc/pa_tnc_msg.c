/*
 * Copyright (C) 2011 Andreas Steffen
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

#include "pa_tnc_msg.h"

#include <tls_writer.h>
#include <tls_reader.h>
#include <utils/linked_list.h>
#include <tnc/pen/pen.h>
#include <debug.h>


typedef struct private_pa_tnc_msg_t private_pa_tnc_msg_t;

/**
 *   PA-TNC message header
 *
 *                        1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Version    |                    Reserved                   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Message Identifier                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PA_TNC_HEADER_SIZE	8
#define PA_TNC_VERSION		0x01
#define PA_TNC_RESERVED		0x000000

/**
 *  PA-TNC attribute 
 *
 *                       1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Flags     |          PA-TNC Attribute Vendor ID           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     PA-TNC Attribute Type                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    PA-TNC Attribute Length                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Attribute Value (Variable Length)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PA_TNC_ATTR_FLAG_NONE			0x00
#define PA_TNC_ATTR_FLAG_NOSKIP			(1<<7)
#define PA_TNC_ATTR_HEADER_SIZE			12

/**
 * Private data of a pa_tnc_msg_t object.
 *
 */
struct private_pa_tnc_msg_t {

	/**
	 * Public pa_tnc_msg_t interface.
	 */
	pa_tnc_msg_t public;

	/**
	 * List of PA-TNC attributes
	 */
	linked_list_t *attributes;

	/**
	 * Message identifier
	 */
	u_int32_t identifier;

	/**
	 * Encoded message
	 */
	chunk_t encoding;
};

METHOD(pa_tnc_msg_t, get_encoding, chunk_t,
	private_pa_tnc_msg_t *this)
{
	return this->encoding;
}

METHOD(pa_tnc_msg_t, add_attribute, void,
	private_pa_tnc_msg_t *this, pa_tnc_attr_t *attr)
{
	this->attributes->insert_last(this->attributes, attr);
}

METHOD(pa_tnc_msg_t, build, void,
	private_pa_tnc_msg_t *this)
{
	tls_writer_t *writer;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_t vendor_id;
	u_int32_t type;
	u_int8_t flags;
	chunk_t value;
	rng_t *rng;

	/* create a random message identifier */
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	rng->get_bytes(rng, sizeof(this->identifier), (u_int8_t*)&this->identifier);
	rng->destroy(rng);
	DBG2(DBG_TNC, "creating PA-TNC message with ID 0x%08x", this->identifier);

	/* build message header */
	writer = tls_writer_create(PA_TNC_HEADER_SIZE);
	writer->write_uint8 (writer, PA_TNC_VERSION);
	writer->write_uint24(writer, PA_TNC_RESERVED);
	writer->write_uint32(writer, this->identifier);

	/* build and append encoding of PA-TNC attributes */
	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attr))
	{
		attr->build(attr);
		vendor_id = attr->get_vendor_id(attr);
		type = attr->get_type(attr);
		value = attr->get_value(attr);
		flags = attr->get_noskip_flag(attr) ? PA_TNC_ATTR_FLAG_NOSKIP :
											  PA_TNC_ATTR_FLAG_NONE;
		DBG2(DBG_TNC, "creating PA-TNC attribute type 0x%06x(%N)/0x%08x",
					   vendor_id, pen_names, vendor_id, type);
		DBG3(DBG_TNC, "%B", &value);

		writer->write_uint8 (writer, flags);
		writer->write_uint24(writer, vendor_id);
		writer->write_uint32(writer, type);
		writer->write_uint32(writer, PA_TNC_ATTR_HEADER_SIZE + value.len);
		writer->write_data  (writer, value);
	}
	enumerator->destroy(enumerator);

	free(this->encoding.ptr);
	this->encoding = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_msg_t, process, status_t,
	private_pa_tnc_msg_t *this)
{
	u_int8_t version;
	u_int32_t reserved;
	tls_reader_t *reader;
	status_t status = FAILED;

	reader = tls_reader_create(this->encoding);

	/* process message header */
	if (reader->remaining(reader) < PA_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PA-TNC message header",
					   this->encoding.len);
		goto end;
	}
	reader->read_uint8 (reader, &version);
	reader->read_uint24(reader, &reserved);
	reader->read_uint32(reader, &this->identifier);

	if (version != PA_TNC_VERSION)
	{
		DBG1(DBG_TNC, "PA-TNC version %u not supported", version);
		goto end;
	}
	DBG2(DBG_TNC, "processing PA-TNC message with ID 0x%08x", this->identifier);
	
	/* pre-process PA-TNC attributes */
	while (reader->remaining(reader) >= PA_TNC_ATTR_HEADER_SIZE)
	{
		pen_t vendor_id;
		u_int8_t flags;
		u_int32_t type, length;
		chunk_t value;
		pa_tnc_attr_t *attr;

		reader->read_uint8 (reader, &flags);
		reader->read_uint24(reader, &vendor_id);
		reader->read_uint32(reader, &type);
		reader->read_uint32(reader, &length);
		DBG2(DBG_TNC, "processing PA-TNC attribute type 0x%06x(%N)/0x%08x",
					   vendor_id, pen_names, vendor_id, type);

		if (length < PA_TNC_ATTR_HEADER_SIZE)
		{
			DBG1(DBG_TNC, "%u bytes too small for PA-TNC attribute length",
						   length);
			goto end;
		}
		length -= PA_TNC_ATTR_HEADER_SIZE;

		if (!reader->read_data(reader, length , &value))
		{
			DBG1(DBG_TNC, "insufficient bytes for PA-TNC attribute value");
			goto end; 
		} 
		DBG3(DBG_TNC, "%B", &value);

		attr = pa_tnc_attr_create_from_data(vendor_id, type, value);
		if (!attr)
		{
			if (flags & PA_TNC_ATTR_FLAG_NOSKIP)
			{
				DBG1(DBG_TNC, "unsupported PA-TNC attribute with NOSKIP flag");
				goto end;
			}
			else
			{
				DBG1(DBG_TNC, "skipping unsupported PA-TNC attribute");
			}
		}

		if (attr->process(attr) != SUCCESS)
		{
			attr->destroy(attr);
			goto end;
		}
		add_attribute(this, attr);
	}

	if (reader->remaining(reader) == 0)
	{
		status = SUCCESS;
	}

end:
	reader->destroy(reader);
	return status;
}

METHOD(pa_tnc_msg_t, create_attribute_enumerator, enumerator_t*,
	private_pa_tnc_msg_t *this)
{
	return this->attributes->create_enumerator(this->attributes);
}

METHOD(pa_tnc_msg_t, destroy, void,
	private_pa_tnc_msg_t *this)
{
	this->attributes->destroy_offset(this->attributes,
									 offsetof(pa_tnc_attr_t, destroy)); 
	free(this->encoding.ptr);
	free(this);
}


/**
 * See header
 */
pa_tnc_msg_t *pa_tnc_msg_create_from_data(chunk_t data)
{
	private_pa_tnc_msg_t *this;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.add_attribute = _add_attribute,
			.build = _build,
			.process = _process,
			.create_attribute_enumerator = _create_attribute_enumerator,
			.destroy = _destroy,
		},
		.encoding = chunk_clone(data),
		.attributes = linked_list_create(),
	);

	return &this->public;
}

/**
 * See header
 */
pa_tnc_msg_t *pa_tnc_msg_create(void)
{
	return pa_tnc_msg_create_from_data(chunk_empty);
}


