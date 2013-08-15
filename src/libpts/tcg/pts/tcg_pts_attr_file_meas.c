/*
 * Copyright (C) 2011-2012 Sansar Choinyambuu, Andreas Steffen
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

#include "tcg_pts_attr_file_meas.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <collections/linked_list.h>
#include <utils/debug.h>

typedef struct private_tcg_pts_attr_file_meas_t private_tcg_pts_attr_file_meas_t;

/**
 * File Measurement
 * see section 3.19.2 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Number of Files included						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Number of Files included						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |		  Request ID		   |	  Measurement Length	    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Measurement #1 (Variable Length)				|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	   Filename Length		 | Filename (Variable Length)		~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~					Filename (Variable Length)					~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Measurement #2 (Variable Length)				|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	   Filename Length		 | Filename (Variable Length)		~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~					Filename (Variable Length)					~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *					 ...........................
 */

#define PTS_FILE_MEAS_SIZE		12

/**
 * Private data of an tcg_pts_attr_file_meas_t object.
 */
struct private_tcg_pts_attr_file_meas_t {

	/**
	 * Public members of tcg_pts_attr_file_meas_t
	 */
	tcg_pts_attr_file_meas_t public;

	/**
	 * Vendor-specific attribute type
	 */
	pen_type_t type;

	/**
	 * Attribute value
	 */
	chunk_t value;

	/**
	 * Noskip flag
	 */
	bool noskip_flag;

	/**
	 * PTS File Measurements
	 */
	pts_file_meas_t *measurements;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(pa_tnc_attr_t, get_type, pen_type_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_file_meas_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_file_meas_t *this)
{
	bio_writer_t *writer;
	enumerator_t *enumerator;
	u_int64_t number_of_files;
	u_int16_t request_id;
	char *filename;
	chunk_t measurement;
	bool first = TRUE;

	if (this->value.ptr)
	{
		return;
	}
	number_of_files = this->measurements->get_file_count(this->measurements);
	request_id = this->measurements->get_request_id(this->measurements);

	writer = bio_writer_create(PTS_FILE_MEAS_SIZE);
	writer->write_uint64(writer, number_of_files);
	writer->write_uint16(writer, request_id);

	enumerator = this->measurements->create_enumerator(this->measurements);
	while (enumerator->enumerate(enumerator, &filename, &measurement))
	{
		if (first)
		{
			writer->write_uint16(writer, measurement.len);
			first = FALSE;
		}
		writer->write_data  (writer, measurement);
		writer->write_data16(writer, chunk_create(filename, strlen(filename)));
	}
	enumerator->destroy(enumerator);

	if (first)
	{
		/* no attached measurements */
		writer->write_uint16(writer, 0);
	}

	this->value = writer->extract_buf(writer);
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_file_meas_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int64_t number_of_files;
	u_int16_t request_id, meas_len;
	chunk_t measurement, filename;
	size_t len;
	char buf[BUF_LEN];
	status_t status = FAILED;

	if (this->value.len < PTS_FILE_MEAS_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for PTS file measurement header");
		*offset = 0;
		return FAILED;
	}

	reader = bio_reader_create(this->value);
	reader->read_uint64(reader, &number_of_files);
	reader->read_uint16(reader, &request_id);
	reader->read_uint16(reader, &meas_len);
	*offset = PTS_FILE_MEAS_SIZE;

	this->measurements = pts_file_meas_create(request_id);

	while (number_of_files--)
	{
		if (!reader->read_data(reader, meas_len, &measurement))
		{
			DBG1(DBG_TNC, "insufficient data for PTS file measurement");
			goto end;
		}
		*offset += meas_len;

		if (!reader->read_data16(reader, &filename))
		{
			DBG1(DBG_TNC, "insufficient data for filename");
			goto end;
		}
		*offset += 2 + filename.len;

		len = min(filename.len, BUF_LEN-1);
		memcpy(buf, filename.ptr, len);
		buf[len] = '\0';
		this->measurements->add(this->measurements, buf, measurement);
	}
	status = SUCCESS;

end:
	reader->destroy(reader);
	return status;
}

METHOD(pa_tnc_attr_t, get_ref, pa_tnc_attr_t*,
	private_tcg_pts_attr_file_meas_t *this)
{
	ref_get(&this->ref);
	return &this->public.pa_tnc_attribute;
}
METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_file_meas_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->measurements);
		free(this->value.ptr);
		free(this);
	}
}

METHOD(tcg_pts_attr_file_meas_t, get_measurements, pts_file_meas_t*,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->measurements;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_file_meas_create(pts_file_meas_t *measurements)
{
	private_tcg_pts_attr_file_meas_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_measurements = _get_measurements,
		},
		.type = { PEN_TCG, TCG_PTS_FILE_MEAS },
		.measurements = measurements,
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_file_meas_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_file_meas_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_measurements = _get_measurements,
		},
		.type = { PEN_TCG, TCG_PTS_FILE_MEAS },
		.value = chunk_clone(data),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}
