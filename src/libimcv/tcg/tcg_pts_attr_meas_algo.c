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

#include "tcg_pts_attr_meas_algo.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_meas_algo_t private_tcg_pts_attr_meas_algo_t;

/**
 * PTS Measurement Algorithm (see section 3.9.1 of PTS Protocol: Binding to TNC IF-M Specification)
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

#define PTS_MEAS_ALGO_SIZE		4
#define PTS_MEAS_ALGO_RESERVED		0x00

/**
 * Private data of an private_tcg_pts_attr_req_proto_caps_t object.
 */
struct private_tcg_pts_attr_meas_algo_t {

	/**
	 * Public members of private_tcg_pts_attr_meas_algo_t
	 */
	tcg_pts_attr_meas_algo_t public;

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
	 * Set of algorithms
	 */
	pts_attr_meas_algorithms_t algorithms;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_meas_algo_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_meas_algo_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_meas_algo_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_meas_algo_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_meas_algo_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_meas_algo_t *this)
{
	bio_writer_t *writer;
	u_int16_t algorithms = 0;

	writer = bio_writer_create(PTS_MEAS_ALGO_SIZE);
	writer->write_uint16 (writer, PTS_MEAS_ALGO_RESERVED);
	
	/* Determine the hash algorithms to set*/
	if(this->algorithms & PTS_MEAS_ALGO_SHA384) algorithms += 8192;
	if(this->algorithms & PTS_MEAS_ALGO_SHA256) algorithms += 16384;
	if(this->algorithms & PTS_MEAS_ALGO_SHA1) algorithms += 32768;
	writer->write_uint16(writer, algorithms);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_meas_algo_t *this)
{
	bio_reader_t *reader;
	u_int16_t reserved;
	u_int16_t algorithms;

	if (this->value.len < PTS_MEAS_ALGO_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for PTS Measurement Algorithm");
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	reader->read_uint16 (reader, &reserved);
	reader->read_uint16(reader, &algorithms);
	
	if((algorithms >> 13) & 1) this->algorithms |= PTS_MEAS_ALGO_SHA384;
	if((algorithms >> 14) & 1) this->algorithms |= PTS_MEAS_ALGO_SHA256;
	if((algorithms >> 15) & 1) this->algorithms |= PTS_MEAS_ALGO_SHA1;
	
	reader->destroy(reader);

	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_meas_algo_t *this)
{
	free(this->value.ptr);
	free(this);
}

METHOD(tcg_pts_attr_meas_algo_t, get_algorithms, pts_attr_meas_algorithms_t,
	private_tcg_pts_attr_meas_algo_t *this)
{
	return this->algorithms;
}

METHOD(tcg_pts_attr_meas_algo_t, set_algorithms, void,
	private_tcg_pts_attr_meas_algo_t *this,
	pts_attr_meas_algorithms_t algorithms)
{
	return this->algorithms = algorithms;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_meas_algo_create(pts_attr_meas_algorithms_t algorithms)
{
	private_tcg_pts_attr_meas_algo_t *this;

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
			.get_algorithms = get_algorithms,
			.set_algorithms = set_algorithms,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_MEAS_ALGO,
		.algorithms = algorithms,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_meas_algo_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_meas_algo_t *this;

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
			.get_algorithms = get_algorithms,
			.set_algorithms = set_algorithms,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_MEAS_ALGO,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
