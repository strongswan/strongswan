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

#include "tcg_pts_attr_aik.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_aik_t private_tcg_pts_attr_aik_t;

/**
 * Attestation Identity Key
 * see section 3.13 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Flags     |    Attestation Identity Key (Variable Length) ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Attestation Identity Key (Variable Length)           ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PTS_AIK_SIZE			4

/**
 * Private data of an tcg_pts_attr_aik_t object.
 */
struct private_tcg_pts_attr_aik_t {

	/**
	 * Public members of tcg_pts_attr_aik_t
	 */
	tcg_pts_attr_aik_t public;

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
	 * Naked Public Key flag
	 */
	bool naked_pub_aik;
	
	/**
	 * Attestation Identity Key
	 */
	chunk_t aik;
};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_aik_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_aik_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_aik_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_aik_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_aik_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_aik_t *this)
{
	bio_writer_t *writer;
	u_int8_t flags = 0;

	writer = bio_writer_create(PTS_AIK_SIZE);
	
	if(this->naked_pub_aik) flags += 128;
	writer->write_uint8 (writer, flags);
	writer->write_data(writer, this->aik);

	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_aik_t *this, u_int32_t *offset)
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
	if((flags >> 7 ) & 1) this->naked_pub_aik = true;
	
	reader->read_data  (reader, this->value.len - 1, &this->aik);
	this->aik = chunk_clone(this->aik);
	reader->destroy(reader);

	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_aik_t *this)
{
	free(this->value.ptr);
	free(this->aik.ptr);
	free(this);
}

METHOD(tcg_pts_attr_aik_t, get_naked_flag, bool,
	private_tcg_pts_attr_aik_t *this)
{
	return this->naked_pub_aik;
}

METHOD(tcg_pts_attr_aik_t, set_naked_flag, void,
	private_tcg_pts_attr_aik_t *this, bool naked_pub_aik)
{
	this->naked_pub_aik = naked_pub_aik;
}

METHOD(tcg_pts_attr_aik_t, get_aik, chunk_t,
	private_tcg_pts_attr_aik_t *this)
{
	return this->aik;
}

METHOD(tcg_pts_attr_aik_t, set_aik, void,
		private_tcg_pts_attr_aik_t *this,
		chunk_t aik)
{
	this->aik = aik;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_aik_create(bool naked_pub_aik, chunk_t aik)
{
	private_tcg_pts_attr_aik_t *this;

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
			.get_naked_flag = _get_naked_flag,
			.set_naked_flag = _set_naked_flag,
			.get_aik = _get_aik,
			.set_aik = _set_aik,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_AIK,
		.naked_pub_aik = naked_pub_aik,
		.aik = aik,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_aik_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_aik_t *this;

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
			.get_naked_flag = _get_naked_flag,
			.set_naked_flag = _set_naked_flag,
			.get_aik = _get_aik,
			.set_aik = _set_aik,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_AIK,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
