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

#include "tcg_pts_attr_req_funct_comp_evid.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_req_funct_comp_evid_t private_tcg_pts_attr_req_funct_comp_evid_t;

/**
 * Request Functional Component Evidence
 * see section 3.14.1 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	 Flags		|			 Sub-component Depth				|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |					Component Functional Name					|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * Component Functional Name Structure (see section 5.1 of PTS Protocol: Binding to TNC IF-M Specification)
 *
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	 Component Functional Name Vendor ID		|Fam| Qualifier |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |					Component Functional Name				  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * Qualifier for Functional Component
 * see section 5.2 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *	
 *	0 1 2 3 4 5
 *  +-+-+-+-+-+-+
 *  |K|S| Type  |
 *  +-+-+-+-+-+-+
 */

#define PTS_REQ_FUNCT_COMP_EVID_SIZE		12
#define PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM		0x00

/**
 * Private data of an tcg_pts_attr_req_funct_comp_evid_t object.
 */
struct private_tcg_pts_attr_req_funct_comp_evid_t {

	/**
	 * Public members of tcg_pts_attr_req_funct_comp_evid_t
	 */
	tcg_pts_attr_req_funct_comp_evid_t public;

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
	 * Set of flags for Request Functional Component
	 */
	pts_attr_req_funct_comp_evid_flag_t flags;

	/**
	 * Sub-component Depth
	 */
	u_int32_t depth;
	
	/**
	 * Component Functional Name Vendor ID
	 */
	u_int32_t comp_vendor_id;
	
	/**
	 * Functional Name Encoding Family
	 */
	u_int8_t family;
	
	/**
	 * Functional Name Category Qualifier
	 */
	pts_qualifier_t qualifier;
	
	/**
	 * Component Functional Name
	 */
	pts_funct_comp_name_t name;
};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	bio_writer_t *writer;
	u_int8_t qualifier = 0;

	writer = bio_writer_create(PTS_REQ_FUNCT_COMP_EVID_SIZE);
	
	writer->write_uint8(writer, this->flags);
	writer->write_uint24 (writer, this->depth);
	writer->write_uint24 (writer, this->comp_vendor_id);
	
	if (this->family != PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM)
	{
		DBG1(DBG_TNC, "Functional Name Encoding Family is not set to 00");
	}
	
	qualifier += this->qualifier.type;
	if (this->qualifier.kernel)
	{
		qualifier += 16;
	}
	if (this->qualifier.sub_component)
	{
		qualifier += 32;
	}
	writer->write_uint8 (writer, qualifier);
	writer->write_uint32 (writer, this->name);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int8_t flags;
	u_int8_t fam_and_qualifier;
	
	if (this->value.len < PTS_REQ_FUNCT_COMP_EVID_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for Request Functional Component Evidence");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	
	reader->read_uint8(reader, &flags);
	if ((flags >> 4) & 1)
	{
		this->flags |= PTS_REQ_FUNC_COMP_FLAG_PCR;
	}
	if ((flags >> 5) & 1)
	{
		this->flags |= PTS_REQ_FUNC_COMP_FLAG_CURR;
	}
	if ((flags >> 6) & 1)
	{
		this->flags |= PTS_REQ_FUNC_COMP_FLAG_VER;
	}
	if ((flags >> 7) & 1)
	{
		this->flags |= PTS_REQ_FUNC_COMP_FLAG_TTC;
	}

	reader->read_uint24(reader, &this->depth);
	reader->read_uint24(reader, &this->comp_vendor_id);
	reader->read_uint8(reader, &fam_and_qualifier);
	
	if (((fam_and_qualifier >> 6) & 1) )
	{
		this->family += 1;
	}
	if (((fam_and_qualifier >> 7) & 1) )
	{
		this->family += 2;
	}
		
	if (((fam_and_qualifier >> 5) & 1) )
	{
		this->qualifier.kernel = true;
	}
	if (((fam_and_qualifier >> 4) & 1) )
	{
		this->qualifier.sub_component = true;
	}
	this->qualifier.type = ( fam_and_qualifier & 0xF );
	reader->read_uint32(reader, &this->name);

	reader->destroy(reader);
	return SUCCESS;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	free(this->value.ptr);
	free(this);
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_flags, pts_attr_req_funct_comp_evid_flag_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->flags;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, set_flags, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, pts_attr_req_funct_comp_evid_flag_t flags)
{
	this->flags = flags;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_sub_component_depth, u_int32_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->depth;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_comp_funct_name_vendor_id, u_int32_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->comp_vendor_id;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_family, u_int8_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->family;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_qualifier, pts_qualifier_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->qualifier;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, set_qualifier, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, pts_qualifier_t qualifier)
{
	this->qualifier = qualifier;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_comp_funct_name, pts_funct_comp_name_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->name;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, set_comp_funct_name, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, pts_funct_comp_name_t name)
{
	this->name = name;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_req_funct_comp_evid_create(
									pts_attr_req_funct_comp_evid_flag_t flags,
									u_int32_t depth, u_int32_t vendor_id,
									pts_qualifier_t qualifier,
									pts_funct_comp_name_t name)
{
	private_tcg_pts_attr_req_funct_comp_evid_t *this;

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
			.get_flags= _get_flags,
			.set_flags= _set_flags,
			.get_sub_component_depth = _get_sub_component_depth,
			.get_comp_funct_name_vendor_id = _get_comp_funct_name_vendor_id,
			.get_family = _get_family,
			.get_qualifier = _get_qualifier,
			.set_qualifier = _set_qualifier,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_FUNCT_COMP_EVID,
		.flags = flags,
		.depth = depth,
		.comp_vendor_id = vendor_id,
		.family = PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM,
		.qualifier = qualifier,
		.name = name,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_req_funct_comp_evid_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_req_funct_comp_evid_t *this;

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
			.get_flags= _get_flags,
			.set_flags= _set_flags,
			.get_sub_component_depth = _get_sub_component_depth,
			.get_comp_funct_name_vendor_id = _get_comp_funct_name_vendor_id,
			.get_family = _get_family,
			.get_qualifier = _get_qualifier,
			.set_qualifier = _set_qualifier,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_FUNCT_COMP_EVID,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
