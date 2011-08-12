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

#include "tcg_pts_attr_file_meas.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/linked_list.h>
/* For pow function */
#include <math.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_file_meas_t private_tcg_pts_attr_file_meas_t;
typedef struct file_meas_entry_t file_meas_entry_t;

/**
 * File Measurement entry
 */
struct file_meas_entry_t {
	chunk_t   measurement;
	u_int16_t file_name_len;
	chunk_t   file_name;
};

/**
 * File Measurement (see section 3.19.2 of PTS Protocol: Binding to TNC IF-M Specification)
 * 
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   		Number of Files included		    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   		Number of Files included		    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |		Request ID    	    | 	Measurement Length	    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   	Measurement #1 (Variable Length)		    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |		Filename Length	    | 	Filename (Variable Length)  ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~			Filename (Variable Length)  		    ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   	Measurement #2 (Variable Length)		    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |		Filename Length	    | 	Filename (Variable Length)  ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~			Filename (Variable Length)  		    ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 			...........................
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
	 * Number of files included
	 */
	u_int64_t number_of_files;
	
	/**
	 * Request ID
	 */
	u_int16_t request_id;
	
	/**
	 * Measurement Length
	 */
	u_int16_t meas_len;
		
	/**
	 * List of File Measurement entries
	 */
	linked_list_t *measurements;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
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
	file_meas_entry_t *entry;
	
	writer = bio_writer_create(PTS_FILE_MEAS_SIZE);

	/* Write the 64 bit integer as 2 parts, first 32 bit and second */
	writer->write_uint32 (writer, (this->number_of_files >> 32));
	writer->write_uint32 (writer, (this->number_of_files & (int)(pow(2,32) - 1)));
	writer->write_uint16(writer, this->request_id);
	writer->write_uint16(writer, this->meas_len);

	enumerator = this->measurements->create_enumerator(this->measurements);
	while (enumerator->enumerate(enumerator, &entry))
	{
		writer->write_data (writer, entry->measurement);
		writer->write_uint16 (writer, entry->file_name_len);
		writer->write_data(writer, entry->file_name);
	}
	enumerator->destroy(enumerator);

	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_file_meas_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int32_t number_of_files;
	u_int64_t number_of_files_64;
	file_meas_entry_t *entry;
	
	if (this->value.len < PTS_FILE_MEAS_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for File Measurement");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	
	reader->read_uint32(reader, &number_of_files);
	number_of_files_64 = number_of_files;
	this->number_of_files = (number_of_files_64 << 32);
	reader->read_uint32(reader, &number_of_files);
	this->number_of_files += number_of_files;
	
	reader->read_uint16(reader, &this->request_id);
	reader->read_uint16(reader, &this->meas_len);
	
	while (reader->remaining(reader))
	{
		entry = malloc_thing(file_meas_entry_t);	
		reader->read_data (reader, this->meas_len, &entry->measurement);
		reader->read_uint16 (reader, &entry->file_name_len);
		reader->read_data(reader, entry->file_name_len, &entry->file_name);
		this->measurements->insert_last(this->measurements, entry);
	}

	reader->destroy(reader);
	return SUCCESS;	
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_file_meas_t *this)
{
	free(this->value.ptr);
	this->measurements->destroy_function(this->measurements, free);
	free(this);
}

METHOD(tcg_pts_attr_file_meas_t, get_number_of_files, u_int64_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->number_of_files;
}

METHOD(tcg_pts_attr_file_meas_t, set_number_of_files, void,
	private_tcg_pts_attr_file_meas_t *this, u_int64_t number_of_files)
{
	this->number_of_files = number_of_files;
}

METHOD(tcg_pts_attr_file_meas_t, get_request_id, u_int16_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->request_id;
}

METHOD(tcg_pts_attr_file_meas_t, set_request_id, void,
	private_tcg_pts_attr_file_meas_t *this, u_int16_t request_id)
{
	this->request_id = request_id;
}

METHOD(tcg_pts_attr_file_meas_t, get_meas_len, u_int16_t,
	private_tcg_pts_attr_file_meas_t *this)
{
	return this->meas_len;
}

METHOD(tcg_pts_attr_file_meas_t, set_meas_len, void,
	private_tcg_pts_attr_file_meas_t *this, u_int16_t meas_len)
{
	this->meas_len = meas_len;
}

METHOD(tcg_pts_attr_file_meas_t, add_file_meas, void,
	private_tcg_pts_attr_file_meas_t *this, chunk_t measurement,
						chunk_t file_name)
{
	file_meas_entry_t *entry;

	entry = malloc_thing(file_meas_entry_t);
	entry->measurement = measurement;
	entry->file_name_len = file_name.len;
	entry->file_name = file_name;
	this->measurements->insert_last(this->measurements, entry);	
}

/**
 * Enumerate file measurement entries
 */
static bool port_filter(void *null, file_meas_entry_t **entry, chunk_t *measurement, 
						void *i2, u_int16_t *file_name_len,
						void *i3, chunk_t *file_name)
{
	*measurement = (*entry)->measurement;
	*file_name_len = (*entry)->file_name_len;
	*file_name = (*entry)->file_name;
	return TRUE;
}

METHOD(tcg_pts_attr_file_meas_t, create_file_meas_enumerator, enumerator_t*,
	private_tcg_pts_attr_file_meas_t *this)
{
	return enumerator_create_filter(this->measurements->create_enumerator(this->measurements),
					(void*)port_filter, NULL, NULL);
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_file_meas_create(
				       u_int64_t number_of_files,
				       u_int16_t request_id,
				       u_int16_t meas_len)
{
	private_tcg_pts_attr_file_meas_t *this;

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
			.get_number_of_files= _get_number_of_files,
			.set_number_of_files= _set_number_of_files,
			.get_request_id = _get_request_id,
			.set_request_id = _set_request_id,
			.get_meas_len = _get_meas_len,
			.set_meas_len = _set_meas_len,
			.add_file_meas = _add_file_meas,
			.create_file_meas_enumerator = _create_file_meas_enumerator,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_FILE_MEAS,
		.number_of_files = number_of_files,
		.request_id = request_id,
		.meas_len = meas_len,
		.measurements = linked_list_create(),
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
				.get_vendor_id = _get_vendor_id,
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.get_number_of_files= _get_number_of_files,
			.set_number_of_files= _set_number_of_files,
			.get_request_id = _get_request_id,
			.set_request_id = _set_request_id,
			.get_meas_len = _get_meas_len,
			.set_meas_len = _set_meas_len,
			.add_file_meas = _add_file_meas,
			.create_file_meas_enumerator = _create_file_meas_enumerator,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_FILE_MEAS,
		.value = chunk_clone(data),
		.measurements = linked_list_create(),
	);

	return &this->public.pa_tnc_attribute;
}
