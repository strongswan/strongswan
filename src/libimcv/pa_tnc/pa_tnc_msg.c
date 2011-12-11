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

#include "imcv.h"
#include "pa_tnc_msg.h"
#include "ietf/ietf_attr_pa_tnc_error.h"

#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/linked_list.h>
#include <pen/pen.h>
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
#define PA_TNC_ATTR_INFO_SIZE			8

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
	 * linked list of PA-TNC error messages
	 */
	linked_list_t *errors;

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
	bio_writer_t *writer;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	enum_name_t *pa_attr_names;
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
	writer = bio_writer_create(PA_TNC_HEADER_SIZE);
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

		pa_attr_names = imcv_pa_tnc_attributes->get_names(imcv_pa_tnc_attributes,
														  vendor_id);
		if (pa_attr_names)
		{
			DBG2(DBG_TNC, "creating PA-TNC attribute type '%N/%N' "
						  "0x%06x/0x%08x", pen_names, vendor_id,
						   pa_attr_names, type, vendor_id, type);
		}
		else
		{
			DBG2(DBG_TNC, "creating PA-TNC attribute type '%N' "
						  "0x%06x/0x%08x", pen_names, vendor_id,
						   vendor_id, type);
		}
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
	bio_reader_t *reader;
	pa_tnc_attr_t *error;
	u_int8_t version;
	u_int32_t reserved, offset, attr_offset;

	/* process message header */
	if (this->encoding.len < PA_TNC_HEADER_SIZE)
	{
		DBG1(DBG_TNC, "%u bytes insufficient to parse PA-TNC message header",
					   this->encoding.len);
		return FAILED;
	}
	reader = bio_reader_create(this->encoding);
	reader->read_uint8 (reader, &version);
	reader->read_uint24(reader, &reserved);
	reader->read_uint32(reader, &this->identifier);
	DBG2(DBG_TNC, "processing PA-TNC message with ID 0x%08x", this->identifier);

	if (version != PA_TNC_VERSION)
	{
		DBG1(DBG_TNC, "PA-TNC version %u not supported", version);
		error = ietf_attr_pa_tnc_error_create(PEN_IETF,
					PA_ERROR_VERSION_NOT_SUPPORTED, this->encoding);
		goto err;
	}
	
	/* offset of the first PA-TNC attribute in the PA-TNC message */
	offset = PA_TNC_HEADER_SIZE;

	/* pre-process PA-TNC attributes */
	while (reader->remaining(reader) >= PA_TNC_ATTR_HEADER_SIZE)
	{
		pen_t vendor_id;
		u_int8_t flags;
		u_int32_t type, length;
		chunk_t value, attr_info;
		pa_tnc_attr_t *attr;
		enum_name_t *pa_attr_names;
		ietf_attr_pa_tnc_error_t *error_attr;

		attr_info = reader->peek(reader);
		attr_info.len = PA_TNC_ATTR_INFO_SIZE;
		reader->read_uint8 (reader, &flags);
		reader->read_uint24(reader, &vendor_id);
		reader->read_uint32(reader, &type);
		reader->read_uint32(reader, &length);

		pa_attr_names = imcv_pa_tnc_attributes->get_names(imcv_pa_tnc_attributes,
														  vendor_id);
		if (pa_attr_names)
		{
			DBG2(DBG_TNC, "processing PA-TNC attribute type '%N/%N' "
						  "0x%06x/0x%08x", pen_names, vendor_id,
						   pa_attr_names, type, vendor_id, type);
		}
		else
		{
			DBG2(DBG_TNC, "processing PA-TNC attribute type '%N' "
						  "0x%06x/0x%08x", pen_names, vendor_id,
						   vendor_id, type);
		}

		if (length < PA_TNC_ATTR_HEADER_SIZE)
		{
			DBG1(DBG_TNC, "%u bytes too small for PA-TNC attribute length",
						   length);
			error = ietf_attr_pa_tnc_error_create_with_offset(PEN_IETF,
						PA_ERROR_INVALID_PARAMETER, this->encoding,
						offset + PA_TNC_ATTR_INFO_SIZE);
			goto err;
		}

		if (!reader->read_data(reader, length - PA_TNC_ATTR_HEADER_SIZE, &value))
		{
			DBG1(DBG_TNC, "insufficient bytes for PA-TNC attribute value");
			error = ietf_attr_pa_tnc_error_create_with_offset(PEN_IETF,
						PA_ERROR_INVALID_PARAMETER, this->encoding,
						offset + PA_TNC_ATTR_INFO_SIZE);
			goto err; 
		} 
		DBG3(DBG_TNC, "%B", &value);

		attr = imcv_pa_tnc_attributes->create(imcv_pa_tnc_attributes,
											  vendor_id, type, value);
		if (!attr)
		{
			if (flags & PA_TNC_ATTR_FLAG_NOSKIP)
			{
				DBG1(DBG_TNC, "unsupported PA-TNC attribute with NOSKIP flag");
				error = ietf_attr_pa_tnc_error_create(PEN_IETF,
							PA_ERROR_ATTR_TYPE_NOT_SUPPORTED, this->encoding);
				error_attr = (ietf_attr_pa_tnc_error_t*)error;
				error_attr->set_attr_info(error_attr, attr_info);
				goto err;
			}
			else
			{
				DBG1(DBG_TNC, "skipping unsupported PA-TNC attribute");
				offset += length;
				continue;
			}
		}

		if (attr->process(attr, &attr_offset) != SUCCESS)
		{
			attr->destroy(attr);
			if (vendor_id == PEN_IETF && type == IETF_ATTR_PA_TNC_ERROR)
			{
				/* error while processing a PA-TNC error attribute - abort */
				reader->destroy(reader);
				return FAILED;
			}
			error = ietf_attr_pa_tnc_error_create_with_offset(PEN_IETF,
						PA_ERROR_INVALID_PARAMETER, this->encoding,
						offset + PA_TNC_ATTR_HEADER_SIZE + attr_offset);
			goto err;
		}
		add_attribute(this, attr);
		offset += length;
	}

	if (reader->remaining(reader) == 0)
	{
		reader->destroy(reader);
		return SUCCESS;
	}
	DBG1(DBG_TNC, "insufficient bytes for PA-TNC attribute header");
	error = ietf_attr_pa_tnc_error_create_with_offset(PEN_IETF,
				PA_ERROR_INVALID_PARAMETER, this->encoding, offset);

err:
	reader->destroy(reader);
	this->errors->insert_last(this->errors, error);
	return VERIFY_ERROR;
}

METHOD(pa_tnc_msg_t, process_ietf_std_errors, bool,
	private_pa_tnc_msg_t *this)
{
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	bool fatal_error = FALSE;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->get_vendor_id(attr) == PEN_IETF &&
			attr->get_type(attr) == IETF_ATTR_PA_TNC_ERROR)
		{
			ietf_attr_pa_tnc_error_t *error_attr;
			pen_t error_vendor_id;
			pa_tnc_error_code_t error_code;
			chunk_t msg_info, attr_info;
			u_int32_t offset;

			error_attr = (ietf_attr_pa_tnc_error_t*)attr;
			error_vendor_id = error_attr->get_vendor_id(error_attr);
			error_code = error_attr->get_error_code(error_attr);
			msg_info = error_attr->get_msg_info(error_attr);

			/* skip errors from non-IETF namespaces */
			if (error_vendor_id != PEN_IETF)
			{
				continue;
			}
			DBG1(DBG_IMC, "received PA-TNC error '%N' concerning message "
				 "0x%08x/0x%08x", pa_tnc_error_code_names, error_code,
				 untoh32(msg_info.ptr), untoh32(msg_info.ptr + 4));

			switch (error_code)
			{
				case PA_ERROR_INVALID_PARAMETER:
					offset = error_attr->get_offset(error_attr);
					DBG1(DBG_IMC, "  occurred at offset of %u bytes", offset);
					break;
				case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
					attr_info = error_attr->get_attr_info(error_attr);
					DBG1(DBG_IMC, "  unsupported attribute %#B", &attr_info);
					break;
				default:
					break;
			}

			/* remove the processed IETF standard error attribute */
			this->attributes->remove_at(this->attributes, enumerator);
			fatal_error = TRUE;
		}
	}
	enumerator->destroy(enumerator);

	return fatal_error;
}

METHOD(pa_tnc_msg_t, create_attribute_enumerator, enumerator_t*,
	private_pa_tnc_msg_t *this)
{
	return this->attributes->create_enumerator(this->attributes);
}

METHOD(pa_tnc_msg_t, create_error_enumerator, enumerator_t*,
	private_pa_tnc_msg_t *this)
{
	return this->errors->create_enumerator(this->errors);
}

METHOD(pa_tnc_msg_t, destroy, void,
	private_pa_tnc_msg_t *this)
{
	this->attributes->destroy_offset(this->attributes,
									 offsetof(pa_tnc_attr_t, destroy)); 
	this->errors->destroy_offset(this->errors,
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
			.process_ietf_std_errors = _process_ietf_std_errors,
			.create_attribute_enumerator = _create_attribute_enumerator,
			.create_error_enumerator = _create_error_enumerator,
			.destroy = _destroy,
		},
		.encoding = chunk_clone(data),
		.attributes = linked_list_create(),
		.errors = linked_list_create(),
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

