/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include "tcg_pts_attr_req_proto_caps.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_req_proto_caps_t private_tcg_pts_attr_req_proto_caps_t;

/**
 * Request PTS Protocol Capabilities
 * see section 3.6 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Reserved                     |C|V|D|T|X|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  
 */

#define PTS_PROTO_CAPS_SIZE		4
#define PTS_PROTO_CAPS_RESERVED		0x00

/**
 * Private data of an tcg_pts_attr_req_proto_caps_t object.
 */
struct private_tcg_pts_attr_req_proto_caps_t {

	/**
	 * Public members of tcg_pts_attr_req_proto_caps_t
	 */
	tcg_pts_attr_req_proto_caps_t public;

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
	 * Set of flags
	 */
	pts_proto_caps_flag_t flags;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_req_proto_caps_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	bio_writer_t *writer;
	u_int8_t flags = 0;

	writer = bio_writer_create(PTS_PROTO_CAPS_SIZE);
	writer->write_uint24 (writer, PTS_PROTO_CAPS_RESERVED);
	
	/* Determine the flags to set*/
	if (this->flags & PTS_PROTO_CAPS_XML)
	{
		flags += 1;
	}
	if (this->flags & PTS_PROTO_CAPS_T)
	{
		flags += 2;
	}
	if (this->flags & PTS_PROTO_CAPS_DH)
	{
		flags += 4;
	}
	if (this->flags & PTS_PROTO_CAPS_VER)
	{
		flags += 8;
	}
	if (this->flags & PTS_PROTO_CAPS_CURRENT)
	{
		flags += 16;
	}
	writer->write_uint8(writer, flags);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_req_proto_caps_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int32_t reserved;
	u_int8_t flags;

	if (this->value.len < PTS_PROTO_CAPS_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for Request PTS Protocol Capabilities");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	reader->read_uint24 (reader, &reserved);
	reader->read_uint8(reader, &flags);
	
	if ((flags >> 0) & 1)
	{
		this->flags |= PTS_PROTO_CAPS_XML;
	}
	if ((flags >> 1) & 1)
	{
		this->flags |= PTS_PROTO_CAPS_T;
	}
	if ((flags >> 2) & 1)
	{
		this->flags |= PTS_PROTO_CAPS_DH;
	}
	if ((flags >> 3) & 1)
	{
		this->flags |= PTS_PROTO_CAPS_VER;
	}
	if ((flags >> 4) & 1)
	{
		this->flags |= PTS_PROTO_CAPS_CURRENT;
	}
	
	reader->destroy(reader);

	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	free(this->value.ptr);
	free(this);
}

METHOD(tcg_pts_attr_req_proto_caps_t, get_flags, pts_proto_caps_flag_t,
	private_tcg_pts_attr_req_proto_caps_t *this)
{
	return this->flags;
}

METHOD(tcg_pts_attr_req_proto_caps_t, set_flags, void,
	private_tcg_pts_attr_req_proto_caps_t *this, pts_proto_caps_flag_t flags)
{
	this->flags = flags;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_req_proto_caps_create(pts_proto_caps_flag_t flags)
{
	private_tcg_pts_attr_req_proto_caps_t *this;

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
			.get_flags = _get_flags,
			.set_flags = _set_flags,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_PROTO_CAPS,
		.flags = flags,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_req_proto_caps_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_req_proto_caps_t *this;

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
			.get_flags = _get_flags,
			.set_flags = _set_flags,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_PROTO_CAPS,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
