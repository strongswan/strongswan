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

#include "tcg_pts_attr_meas_algo_selection.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_meas_algo_selection_t private_tcg_pts_attr_meas_algo_selection_t;

/**
 * PTS Measurement Algorithm Selection (see section 3.9.2 of PTS Protocol: Binding to TNC IF-M Specification)
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Reserved           |       Hash Algorithm Set      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  
 */

/**
 * Diffie-Hellman Hash Algorithm Values (see section 3.8.5 of PTS Protocol: Binding to TNC IF-M Specification)
 *
 *                       1          
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |1|2|3|R|R|R|R|R|R|R|R|R|R|R|R|R|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  
 */

#define PTS_MEAS_ALGO_SEL_SIZE		4
#define PTS_MEAS_ALGO_SEL_RESERVED	0x00

/**
 * Private data of an private_tcg_pts_attr_meas_algo_selection_t object.
 */
struct private_tcg_pts_attr_meas_algo_selection_t {

	/**
	 * Public members of private_tcg_pts_attr_meas_algo_t
	 */
	tcg_pts_attr_meas_algo_selection_t public;

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
	 * A Selected Measurement Algorithm
	 */
	pts_attr_meas_algorithms_t algorithm;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_meas_algo_selection_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	bio_writer_t *writer;
	u_int16_t algorithm = 0;

	writer = bio_writer_create(PTS_MEAS_ALGO_SEL_SIZE);
	writer->write_uint16 (writer, PTS_MEAS_ALGO_SEL_RESERVED);
	
	/* Determine the hash algorithm to set*/
	if(this->algorithm & PTS_MEAS_ALGO_SHA384) algorithm = 8192;
	else if(this->algorithm & PTS_MEAS_ALGO_SHA256) algorithm = 16384;
	else if(this->algorithm & PTS_MEAS_ALGO_SHA1) algorithm = 32768;
	writer->write_uint16(writer, algorithm);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	bio_reader_t *reader;
	u_int16_t reserved;
	u_int16_t algorithm;

	if (this->value.len < PTS_MEAS_ALGO_SEL_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for PTS Measurement Algorithm Selection");
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	reader->read_uint16 (reader, &reserved);
	reader->read_uint16(reader, &algorithm);
	
	if((algorithm >> 13) & 1) this->algorithm = PTS_MEAS_ALGO_SHA384;
	else if((algorithm >> 14) & 1) this->algorithm = PTS_MEAS_ALGO_SHA256;
	else if((algorithm >> 15) & 1) this->algorithm = PTS_MEAS_ALGO_SHA1;
	
	reader->destroy(reader);

	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	free(this->value.ptr);
	free(this);
}

METHOD(tcg_pts_attr_meas_algo_t, get_algorithm, pts_attr_meas_algorithms_t,
	private_tcg_pts_attr_meas_algo_selection_t *this)
{
	return this->algorithms;
}

METHOD(tcg_pts_attr_meas_algo_t, set_algorithm, void,
	private_tcg_pts_attr_meas_algo_selection_t *this,
	pts_attr_meas_algorithms_t algorithm)
{
	return this->algorithm = algorithm;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_meas_algo_create(pts_attr_meas_algorithms_t algorithm)
{
	private_tcg_pts_attr_meas_algo_selection_t *this;

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
			.get_algorithm = get_algorithm,
			.set_algorithm = set_algorithm,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_MEAS_ALGO_SELECTION,
		.algorithm = algorithm,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_meas_algo_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_meas_algo_selection_t *this;

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
			.get_algorithm = get_algorithm,
			.set_algorithm = set_algorithm,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_MEAS_ALGO_SELECTION,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
