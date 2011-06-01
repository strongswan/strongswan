/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "ietf_attr_pa_tnc_error.h"

#include <bio/bio_writer.h>
#include <debug.h>

ENUM(pa_tnc_error_code_names, PA_ERROR_RESERVED,
							  PA_ERROR_ATTR_TYPE_NOT_SUPPORTED,
	"Reserved",
	"Invalid Parameter",
	"Version Not Supported",
	"Attribute Type Not Supported"
);

typedef struct private_ietf_attr_pa_tnc_error_t private_ietf_attr_pa_tnc_error_t;

/**
 * PA-TNC Error Attribute Type  (see section 4.2.8 of RFC 5792)
 *
 *                        1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Reserved   |            PA-TNC Error Code Vendor ID        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        PA-TNC Error Code                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Error Information (Variable Length)           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define IETF_ATTR_PA_TNC_ERROR_HEADER_SIZE	12
#define IETF_ATTR_PA_TNC_ERROR_RESERVED		0x00

/**
 * Private data of an ietf_attr_pa_tnc_error_t object.
 */
struct private_ietf_attr_pa_tnc_error_t {

	/**
	 * Public members of ietf_attr_pa_tnc_error_t
	 */
	ietf_attr_pa_tnc_error_t public;

	/**
	 * Attribute vendor ID
	 */
	pen_t vendor_id;

	/**
	 * Attribute type
	 */
	u_int32_t type;

	/**
	 * Attribute value
	 */
	chunk_t value;

	/**
	 * Noskip flag
	 */
	bool noskip_flag;

	/**
	 * Error code vendor ID
	 */
	pen_t error_vendor_id;

	/**
	 * Error code
	 */
	u_int32_t error_code;

	/**
	 * PA-TNC message header
	 */
	chunk_t header;
};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_ietf_attr_pa_tnc_error_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_ietf_attr_pa_tnc_error_t *this)
{
	bio_writer_t *writer;

	writer = bio_writer_create(IETF_ATTR_PA_TNC_ERROR_HEADER_SIZE);
	writer->write_uint8 (writer, IETF_ATTR_PA_TNC_ERROR_RESERVED);
	writer->write_uint24(writer, this->error_vendor_id);
	writer->write_uint32(writer, this->error_code);
	writer->write_data  (writer, this->header);
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_ietf_attr_pa_tnc_error_t *this)
{
	free(this->header.ptr);
	free(this);
}

METHOD(ietf_attr_pa_tnc_error_t, get_error_vendor_id, pen_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->error_vendor_id;
}

METHOD(ietf_attr_pa_tnc_error_t, get_error_code, u_int32_t,
	private_ietf_attr_pa_tnc_error_t *this)
{
	return this->error_code;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_attr_pa_tnc_error_create(pen_t vendor_id,
											 u_int32_t error_code,
											 chunk_t header)
{
	private_ietf_attr_pa_tnc_error_t *this;

	header.len = 8;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_vendor_id = _get_vendor_id,
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_vendor_id = _get_error_vendor_id,
			.get_error_code = _get_error_code,
		},
		.vendor_id = PEN_IETF,
		.type = IETF_ATTR_PA_TNC_ERROR,
		.error_vendor_id = vendor_id,
		.error_code = error_code,
		.header = chunk_clone(header),
	);

	return &this->public.pa_tnc_attribute;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_attr_pa_tnc_error_create_from_data(chunk_t data)
{
	private_ietf_attr_pa_tnc_error_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_vendor_id = _get_vendor_id,
				.get_type = _get_type,
				.get_value = _get_value,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_vendor_id = _get_error_vendor_id,
			.get_error_code = _get_error_code,
		},
		.vendor_id = PEN_IETF,
		.type = IETF_ATTR_PA_TNC_ERROR,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}


