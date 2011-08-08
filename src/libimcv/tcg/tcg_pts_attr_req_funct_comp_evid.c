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
 * Request Functional Component Evidence (see section 3.14.1 of PTS Protocol: Binding to TNC IF-M Specification)
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Flags     |             Sub-component Depth               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Component Functional Name                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * Component Functional Name Structure (see section 5.1 of PTS Protocol: Binding to TNC IF-M Specification)
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Component Functional Name Vendor ID	    |Fam| Qualifier |                 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Component Functional Name                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#define PTS_REQ_FUNCT_COMP_EVID_SIZE		12
#define PTS_REQ_FUNCT_COMP_EVID_RESERVED	0x00

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
	u_int8_t qualifier;
	
	/**
	 * Component Functional Name
	 */
	u_int32_t name;
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
	u_int8_t flags = 0;
	u_int8_t family_and_qualifier = 0;

	writer = bio_writer_create(PTS_REQ_FUNCT_COMP_EVID_SIZE);
	
	/* Determine the flags to set*/
	if(this->flags & PTS_REQ_FUNC_COMP_TTC) flags += 1;
	if(this->flags & PTS_REQ_FUNC_COMP_VER) flags += 2;
	if(this->flags & PTS_REQ_FUNC_COMP_CURR) flags += 4;
	if(this->flags & PTS_REQ_FUNC_COMP_PCR) flags += 8;
	writer->write_uint8(writer, flags);
	
	writer->write_uint24 (writer, this->depth);
	writer->write_uint24 (writer, this->comp_vendor_id);
	
	if(this->family)
	{
		DBG1(DBG_TNC, "Functional Name Encoding Family must be set to 00");
	}
	
	writer->write_uint8 (writer, this->depth);
	writer->write_uint24 (writer, this->depth);
	writer->write_uint24 (writer, this->depth);
	writer->write_uint24 (writer, this->depth);
	
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int8_t flags;
	
	if (this->value.len < PTS_AIK_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for Attestation Identity Key");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	
	reader->read_uint8(reader, &flags);
	if(flags) this->naked_pub_aik = true;
	
	reader->read_data  (reader, sizeof(this->value) - 1, &this->aik);
	this->aik = chunk_clone(this->aik);
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

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_qualifier, u_int8_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->qualifier;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, set_fam_qual, void,
		private_tcg_pts_attr_req_funct_comp_evid_t *this,
		u_int8_t family, u_int8_t qualifier)
{
	this->family = family;
	this->qualifier = qualifier;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, get_comp_funct_name, u_int32_t,
	private_tcg_pts_attr_req_funct_comp_evid_t *this)
{
	return this->name;
}

METHOD(tcg_pts_attr_req_funct_comp_evid_t, set_comp_funct_name, void,
	private_tcg_pts_attr_req_funct_comp_evid_t *this, u_int32_t name)
{
	this->name = name;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_req_funct_comp_evid_create(
				       pts_attr_req_funct_comp_evid_flag_t flags,
				       u_int32_t depth, 
				       u_int32_t vendor_id,
				       u_int8_t family,
				       u_int8_t qualifier,
				       u_int32_t name)
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
			.set_fam_qual = _set_fam_qual,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_FUNCT_COMP_EVID,
		.flags = flags,
		.depth = depth,
		.comp_vendor_id = vendor_id,
		.family = family,
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
			.set_fam_qual = _set_fam_qual,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_REQ_FUNCT_COMP_EVID,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
