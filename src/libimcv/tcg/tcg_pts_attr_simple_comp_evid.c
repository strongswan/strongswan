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

#include "tcg_pts_attr_simple_comp_evid.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_simple_comp_evid_t private_tcg_pts_attr_simple_comp_evid_t;

/**
 * Simple Component Evidence 
 * see section 3.15.1 of PTS Protocol: Binding to TNC IF-M Specification
 * 
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Flags     |                Sub-Component Depth            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Specific Functional Component                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Specific Functional Component                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Measure. Type |                Extended into PCR              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Hash Algorithm        | PCR Transform |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Measurement Date/Time                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Measurement Date/Time                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Measurement Date/Time                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Measurement Date/Time                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Measurement Date/Time                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Optional Policy URI Length   |  Opt. Verification Policy URI ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~                 Optional Verification Policy URI              ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Optional PCR Length       |   Optional PCR Before Value   ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~            Optional PCR Before Value (Variable Length)        ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~            Optional PCR After Value (Variable Length)         ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~            Component Measurement (Variable Length)            ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * Specific Functional Component -> Component Functional Name Structure 
 * see section 5.1 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Component Functional Name Vendor ID	    |Fam| Qualifier |                 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Component Functional Name                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * Qualifier for Functional Component
 * see section 5.2 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *                 
 *   0 1 2 3 4 5 
 *  +-+-+-+-+-+-+
 *  |K|S| Type  |
 *  +-+-+-+-+-+-+
 */



#define PTS_SIMPLE_COMP_EVID_SIZE					40
#define PTS_SIMPLE_COMP_EVID_MEASUREMENT_TIME_SIZE	20
#define PTS_SIMPLE_COMP_EVID_RESERVED				0x00
#define PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM				0x00

/**
 * Private data of an tcg_pts_attr_simple_comp_evid_t object.
 */
struct private_tcg_pts_attr_simple_comp_evid_t {

	/**
	 * Public members of tcg_pts_attr_simple_comp_evid_t
	 */
	tcg_pts_attr_simple_comp_evid_t public;

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
	 * Set of flags for Simple Component Evidence
	 */
	pts_attr_simple_comp_evid_flag_t flags;

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
	tcg_pts_qualifier_t qualifier;
	
	/**
	 * Component Functional Name
	 */
	pts_attr_req_funct_comp_name_bin_enum_t name;
	
	/**
	 * Measurement type
	 */
	u_int8_t measurement_type;
	
	/**
	 * Which PCR the functional component is extended into 
	 */
	u_int32_t extended_pcr;
	
	/**
	 * Hash Algorithm
	 */
	pts_meas_algorithms_t hash_algorithm;
	
	/**
	 * Transformation type for PCR 
	 */
	pts_pcr_transform_t transformation;
	
	/**
	 * Measurement time
	 */
	chunk_t measurement_time;
	
	/**
	 * Optional Policy URI
	 */
	chunk_t policy_uri;
	
	/**
	 * Optional PCR before value
	 */
	chunk_t pcr_before;
	
	/**
	 * Optional PCR after value
	 */
	chunk_t pcr_after;
	
	/**
	 * Component Measurement
	 */
	chunk_t measurement;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_simple_comp_evid_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	bio_writer_t *writer;
	u_int8_t flags = 0;
	u_int8_t qualifier = 0;
	
	writer = bio_writer_create(PTS_SIMPLE_COMP_EVID_SIZE);
	
	/* Determine the flags to set*/
	if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_PCR)
	{
		flags += 128;
	}
	if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_NO_VER)
	{
		flags += 32;
	}
	else if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_VER_FAIL)
	{
		flags += 64;
	}
	else if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_VER_PASS)
	{
		flags += 96;
	}
	
	writer->write_uint8(writer, flags);
	
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
	
	/* Unknown or Wildcard should not be used for Qualification*/
	if (!qualifier || qualifier == 63)
	{
		DBG1(DBG_TNC, "Unknown or Wildcard should not be used for"
			      " Functional Name Qualifier");
	}
	
	writer->write_uint8 (writer, qualifier);
	writer->write_uint32(writer, this->name);
	
	writer->write_uint8 (writer, (this->measurement_type << 7));
	writer->write_uint24(writer, this->extended_pcr);
	writer->write_uint16(writer, this->hash_algorithm);
	writer->write_uint8 (writer, this->transformation);
	writer->write_data  (writer, this->measurement_time);
	
	/* Optional fields */
	if (this->policy_uri.ptr && this->policy_uri.len > 0) 
	{
		writer->write_uint16(writer, this->policy_uri.len);
		writer->write_data  (writer, this->policy_uri);
	}
	if (this->pcr_before.ptr && this->pcr_after.ptr &&
		this->pcr_before.len == this->pcr_after.len &&
		this->pcr_before.len > 0 && this->pcr_after.len > 0)
	{
		writer->write_uint16(writer, this->pcr_before.len);
		writer->write_data  (writer, this->pcr_before);
		writer->write_data  (writer, this->pcr_after);
	}
	
	writer->write_data (writer, this->measurement);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_simple_comp_evid_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int8_t flags;
	u_int8_t fam_and_qualifier;
	u_int8_t measurement_type;
	u_int16_t algorithm;
	u_int8_t transformation;
	u_int32_t measurement_len;
	
	if (this->value.len < PTS_SIMPLE_COMP_EVID_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for Simple Component Evidence");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	
	reader->read_uint8(reader, &flags);
	
	/* Determine the flags to set*/
	if ((flags >> 7) & 1)
	{
 		this->flags |= PTS_SIMPLE_COMP_EVID_FLAG_PCR;
	}
	if (!((flags >> 6) & 1) && !((flags >> 5) & 1))
	{
		this->flags |= PTS_SIMPLE_COMP_EVID_FLAG_NO_VALID;
	}
	else if (!((flags >> 6) & 1) && ((flags >> 5) & 1))
	{ 
		this->flags |= PTS_SIMPLE_COMP_EVID_FLAG_NO_VER;
	}
	else if (((flags >> 6) & 1) && !((flags >> 5) & 1))
	{
		this->flags |= PTS_SIMPLE_COMP_EVID_FLAG_VER_FAIL;
	}
	else if (((flags >> 6) & 1) && ((flags >> 5) & 1))
	{
		this->flags |= PTS_SIMPLE_COMP_EVID_FLAG_VER_PASS;
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
	
	/* TODO: Generate an IF-M error attribute indicating */
	/* TCG_PTS_INVALID_NAME_FAM */
	//if(&this->comp_vendor_id==PEN_TCG && this->family != PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM)
	//{
	//	DBG1(DBG_TNC, "Functional Name Encoding Family is not set to 00");
	//}
	
	if (((fam_and_qualifier >> 5) & 1) )
	{
		this->qualifier.kernel = true;
	}
	if (((fam_and_qualifier >> 4) & 1) ) 
	{
		this->qualifier.sub_component = true;
	}
	this->qualifier.type = ( fam_and_qualifier & 0xF );
	/* TODO: Check the type is defined in pts_attr_req_funct_comp_type_t */

	/* Unknown or Wildcard should not be used for Qualification*/
	if (!(fam_and_qualifier & 0x3F) || (fam_and_qualifier & 0x3F) == 0x3F)
	{
		DBG1(DBG_TNC, "Unknown or Wildcard should not be used for"
			      " Functional Name Qualifier");
	}
	
	reader->read_uint32(reader, &this->name);
	/* TODO: Check the name is defined in pts_attr_req_funct_comp_name_bin_enum_t */
	
	reader->read_uint8(reader, &measurement_type);
	this->measurement_type = (measurement_type >> 7 ) & 1;
	
	reader->read_uint24(reader, &this->extended_pcr);
	reader->read_uint16(reader, &algorithm);
	this->hash_algorithm = algorithm;	
	
	reader->read_uint8(reader, &transformation);
	this->transformation = transformation;
	/* TODO: Check the transformation is defined in pts_pcr_transform_t */
	
	reader->read_data(reader, PTS_SIMPLE_COMP_EVID_MEASUREMENT_TIME_SIZE,
			  &this->measurement_time);
	
	/*  Optional Policy URI field is included */
	if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_VER_FAIL || 
		this->flags & PTS_SIMPLE_COMP_EVID_FLAG_VER_PASS)
	{
		u_int16_t policy_uri_len;
		reader->read_uint16(reader, &policy_uri_len);
		reader->read_data(reader, policy_uri_len, &this->policy_uri);
	}
	
	/*  Optional PCR value fields are included */
	if (this->flags & PTS_SIMPLE_COMP_EVID_FLAG_PCR)
	{
		u_int16_t pcr_value_len;
		reader->read_uint16(reader, &pcr_value_len);
		reader->read_data(reader, pcr_value_len, &this->pcr_before);
		reader->read_data(reader, pcr_value_len, &this->pcr_after);
	}
	
	measurement_len = reader->remaining(reader);
	reader->read_data(reader, measurement_len, &this->measurement);

	reader->destroy(reader);
	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	free(this->value.ptr);
	free(this->measurement_time.ptr);
	free(this->policy_uri.ptr);
	free(this->pcr_before.ptr);
	free(this->pcr_after.ptr);
	free(this->measurement.ptr);
	free(this);
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_flags, pts_attr_simple_comp_evid_flag_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->flags;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_flags, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, pts_attr_simple_comp_evid_flag_t flags)
{
	this->flags = flags;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_sub_component_depth, u_int32_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->depth;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_spec_comp_funct_name_vendor_id, u_int32_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->comp_vendor_id;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_family, u_int8_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->family;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_qualifier, tcg_pts_qualifier_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->qualifier;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_qualifier, void,
		private_tcg_pts_attr_simple_comp_evid_t *this,
		tcg_pts_qualifier_t qualifier)
{
	this->qualifier = qualifier;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_comp_funct_name, pts_attr_req_funct_comp_name_bin_enum_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->name;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_comp_funct_name, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, pts_attr_req_funct_comp_name_bin_enum_t name)
{
	this->name = name;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_measurement_type, u_int8_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->measurement_type;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_extended_pcr, u_int32_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->extended_pcr;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_extended_pcr, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, u_int32_t extended_pcr)
{
	this->extended_pcr = extended_pcr;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_hash_algorithm, pts_meas_algorithms_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->hash_algorithm;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_hash_algorithm, void,
	private_tcg_pts_attr_simple_comp_evid_t *this,
	pts_meas_algorithms_t hash_algorithm)
{
	this->hash_algorithm = hash_algorithm;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_pcr_trans, pts_pcr_transform_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->transformation;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_pcr_trans, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, pts_pcr_transform_t transformation)
{
	this->transformation = transformation;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_measurement_time, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->measurement_time;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_measurement_time, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, chunk_t measurement_time)
{
	this->measurement_time = measurement_time;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_policy_uri, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->policy_uri;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_policy_uri, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, chunk_t policy_uri)
{
	this->policy_uri = policy_uri;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_pcr_before_value, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->pcr_before;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_pcr_before_value, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, chunk_t pcr_before)
{
	this->pcr_before = pcr_before;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_pcr_after_value, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->pcr_after;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_pcr_after_value, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, chunk_t pcr_after)
{
	this->pcr_after = pcr_after;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_pcr_len, u_int16_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	if(this->pcr_before.ptr && this->pcr_after.ptr && 
		this->pcr_before.len == this->pcr_after.len &&
		this->pcr_before.len > 0 && this->pcr_after.len > 0) 
			return this->pcr_before.len;
	else return 0;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, get_comp_measurement, chunk_t,
	private_tcg_pts_attr_simple_comp_evid_t *this)
{
	return this->measurement;
}

METHOD(tcg_pts_attr_simple_comp_evid_t, set_comp_measurement, void,
	private_tcg_pts_attr_simple_comp_evid_t *this, chunk_t measurement)
{
	this->measurement = measurement;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_simple_comp_evid_create(
				       pts_attr_simple_comp_evid_flag_t flags,
				       u_int32_t depth, 
				       u_int32_t vendor_id,
				       tcg_pts_qualifier_t qualifier,
				       pts_attr_req_funct_comp_name_bin_enum_t name,
				       u_int32_t extended_pcr,
				       pts_meas_algorithms_t hash_algorithm,
				       pts_pcr_transform_t transformation,
				       chunk_t measurement_time,
				       chunk_t policy_uri,
				       chunk_t pcr_before,
				       chunk_t pcr_after,
				       chunk_t measurement)
{
	private_tcg_pts_attr_simple_comp_evid_t *this;

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
			.get_spec_comp_funct_name_vendor_id = _get_spec_comp_funct_name_vendor_id,
			.get_family = _get_family,
			.get_qualifier = _get_qualifier,
			.set_qualifier = _set_qualifier,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
			.get_measurement_type = _get_measurement_type,
			.get_extended_pcr = _get_extended_pcr,
			.set_extended_pcr = _set_extended_pcr,
			.get_hash_algorithm = _get_hash_algorithm,
			.set_hash_algorithm = _set_hash_algorithm,
			.get_pcr_trans = _get_pcr_trans,
			.set_pcr_trans = _set_pcr_trans,
			.get_measurement_time = _get_measurement_time,
			.set_measurement_time = _set_measurement_time,
			.get_policy_uri = _get_policy_uri,
			.set_policy_uri = _set_policy_uri,
			.get_pcr_before_value = _get_pcr_before_value,
			.set_pcr_before_value = _set_pcr_before_value,
			.get_pcr_after_value = _get_pcr_after_value,
			.set_pcr_after_value = _set_pcr_after_value,
			.get_pcr_len = _get_pcr_len,
			.get_comp_measurement = _get_comp_measurement,
			.set_comp_measurement = _set_comp_measurement,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_SIMPLE_COMP_EVID,
		.flags = flags,
		.depth = depth,
		.comp_vendor_id = vendor_id,
		.family = PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM,
		.qualifier = qualifier,
		.name = name,
		.extended_pcr = extended_pcr,
		.hash_algorithm = hash_algorithm,
		.transformation = transformation,
		.measurement_time = measurement_time,
		.policy_uri = policy_uri,
		.pcr_before = pcr_before,
		.pcr_after = pcr_after,
		.measurement = measurement,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_simple_comp_evid_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_simple_comp_evid_t *this;

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
			.get_spec_comp_funct_name_vendor_id = _get_spec_comp_funct_name_vendor_id,
			.get_family = _get_family,
			.get_qualifier = _get_qualifier,
			.set_qualifier = _set_qualifier,
			.get_comp_funct_name = _get_comp_funct_name,
			.set_comp_funct_name = _set_comp_funct_name,
			.get_measurement_type = _get_measurement_type,
			.get_extended_pcr = _get_extended_pcr,
			.set_extended_pcr = _set_extended_pcr,
			.get_hash_algorithm = _get_hash_algorithm,
			.set_hash_algorithm = _set_hash_algorithm,
			.get_pcr_trans = _get_pcr_trans,
			.set_pcr_trans = _set_pcr_trans,
			.get_measurement_time = _get_measurement_time,
			.set_measurement_time = _set_measurement_time,
			.get_policy_uri = _get_policy_uri,
			.set_policy_uri = _set_policy_uri,
			.get_pcr_before_value = _get_pcr_before_value,
			.set_pcr_before_value = _set_pcr_before_value,
			.get_pcr_after_value = _get_pcr_after_value,
			.set_pcr_after_value = _set_pcr_after_value,
			.get_pcr_len = _get_pcr_len,
			.get_comp_measurement = _get_comp_measurement,
			.set_comp_measurement = _set_comp_measurement,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_SIMPLE_COMP_EVID,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
