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

#include "tcg_pts_attr_unix_file_meta.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_file_meta_t private_tcg_pts_attr_file_meta_t;

/**
 * Unix-Style File Metadata
 * see section 3.17.3 of PTS Protocol: Binding to TNC IF-M Specification
 * 
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Number of Files included						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				   Number of Files included						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	File metadata Length	    |	 Type	    |	Reserved	|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |							File Size							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |							File Size							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Create Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Create Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						Last Modify Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						Last Modify Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						Last Access Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						Last Access Time						|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Owner ID							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Owner ID							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Group ID							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |						File Group ID							|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~					Filename (Variable Length)					~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *					 ...........................
 */

#define PTS_FILE_META_SIZE			8
#define PTS_FILE_MEAS_RESERVED		0x00

/**
 * Private data of an tcg_pts_attr_file_meta_t object.
 */
struct private_tcg_pts_attr_file_meta_t {

	/**
	 * Public members of tcg_pts_attr_file_meta_t
	 */
	tcg_pts_attr_file_meta_t public;

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
	 * PTS File Metadata
	 */
	pts_file_meta_t *metadata;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_file_meta_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_file_meta_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_file_meta_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_file_meta_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_file_meta_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_file_meta_t *this)
{
	bio_writer_t *writer;
	enumerator_t *enumerator;
	pts_file_metadata_t *entry;
	u_int64_t number_of_files;
	
	number_of_files = this->metadata->get_file_count(this->metadata);
	writer = bio_writer_create(PTS_FILE_META_SIZE);

	/* Write the 64 bit integer field - number of files as two 32 bit parts */
	writer->write_uint32(writer, number_of_files >> 32);
	writer->write_uint32(writer, number_of_files & 0xffffffff);

	enumerator = this->metadata->create_enumerator(this->metadata);
	while (enumerator->enumerate(enumerator, &entry))
	{
		writer->write_uint16(writer, PTS_FILE_METADATA_SIZE + strlen(entry->filename));
		writer->write_uint8 (writer, entry->type);
		writer->write_uint8 (writer, PTS_FILE_MEAS_RESERVED);

		/* Write the 64 bit integer fields as two 32 bit parts */
		writer->write_uint32(writer, entry->filesize >> 32);
		writer->write_uint32(writer, entry->filesize & 0xffffffff);
		writer->write_uint32(writer, ((u_int64_t)entry->create_time) >> 32);
		writer->write_uint32(writer, ((u_int64_t)entry->create_time) & 0xffffffff);
		writer->write_uint32(writer, ((u_int64_t)entry->last_modify_time) >> 32);
		writer->write_uint32(writer, ((u_int64_t)entry->last_modify_time) & 0xffffffff);
		writer->write_uint32(writer, ((u_int64_t)entry->last_access_time) >> 32);
		writer->write_uint32(writer, ((u_int64_t)entry->last_access_time) & 0xffffffff);
		writer->write_uint32(writer, entry->owner_id >> 32);
		writer->write_uint32(writer, entry->owner_id & 0xffffffff);
		writer->write_uint32(writer, entry->group_id >> 32);
		writer->write_uint32(writer, entry->group_id & 0xffffffff);
		
		writer->write_data  (writer, chunk_create(entry->filename, strlen(entry->filename)));
	}
	enumerator->destroy(enumerator);
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_file_meta_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	pts_file_metadata_t *entry;
	
	int number_of_files;
	u_int32_t number_of_files32;
	
	u_int16_t meta_length;
	pts_file_type_t type;
	u_int8_t type8;
	u_int8_t reserved;
	
	int filesize;
	u_int32_t filesize32;
	
	int create_time;
	u_int32_t create_time32;
	time_t create_time_t;
	int modify_time;
	u_int32_t modify_time32;
	time_t modify_time_t;
	int access_time;
	u_int32_t access_time32;
	time_t access_time_t;
	
	int owner_id;
	u_int32_t owner_id32;

	int group_id;
	u_int32_t group_id32;
	
	size_t len;
	chunk_t filename;
	char buf[BUF_LEN];
	status_t status = FAILED;
	
	if (this->value.len < PTS_FILE_META_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for PTS Unix-Style file metadata header");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);

	reader->read_uint32(reader, &number_of_files32);
	number_of_files = (sizeof(number_of_files) > 4) ? number_of_files32 << 32 : 0;
	reader->read_uint32(reader, &number_of_files32);
	number_of_files += number_of_files32;
		
	this->metadata = pts_file_meta_create();
	
	while (number_of_files--)
	{
		if (!reader->read_uint16(reader, &meta_length))
		{
			DBG1(DBG_TNC, "insufficient data for PTS file metadata length");
			goto end;
		}
		if (!reader->read_uint8 (reader, &type8))
		{
			DBG1(DBG_TNC, "insufficient data for file type");
			goto end;
		}
		type = (pts_file_type_t)type8;
		if (!reader->read_uint8 (reader, &reserved))
		{
			DBG1(DBG_TNC, "insufficient data for reserved field");
			goto end;
		}
		if (!reader->read_uint32(reader, &filesize32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		filesize = (sizeof(filesize) > 4) ? filesize32 << 32 : 0;
		if (!reader->read_uint32(reader, &filesize32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		filesize += filesize32;
		
		if (!reader->read_uint32(reader, &create_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		create_time = (sizeof(create_time) > 4) ? create_time32 << 32 : 0;
		if (!reader->read_uint32(reader, &create_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		create_time += create_time32;
		create_time_t = (time_t)create_time;
		
		if (!reader->read_uint32(reader, &modify_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		modify_time = (sizeof(modify_time) > 4) ? modify_time32 << 32 : 0;
		if (!reader->read_uint32(reader, &modify_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		modify_time += modify_time32;
		modify_time_t = (time_t)modify_time;
		
		if (!reader->read_uint32(reader, &access_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		access_time = (sizeof(access_time) > 4) ? access_time32 << 32 : 0;
		if (!reader->read_uint32(reader, &access_time32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		access_time += access_time32;
		access_time_t = (time_t)access_time;

		if (!reader->read_uint32(reader, &owner_id32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		owner_id = (sizeof(owner_id) > 4) ? owner_id32 << 32 : 0;
		if (!reader->read_uint32(reader, &owner_id32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		owner_id += owner_id32;

		if (!reader->read_uint32(reader, &group_id32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		group_id = (sizeof(group_id) > 4) ? group_id32 << 32 : 0;
		if (!reader->read_uint32(reader, &group_id32))
		{
			DBG1(DBG_TNC, "insufficient data for file size");
			goto end;
		}
		group_id += group_id32;

		if (!reader->read_data(reader, meta_length - PTS_FILE_METADATA_SIZE, &filename))
		{
			DBG1(DBG_TNC, "insufficient data for filename");
			goto end;
		}
		
		len = min(filename.len, BUF_LEN - 1);
		memcpy(buf, filename.ptr, len);
		buf[len] = '\0';

		entry = malloc_thing(pts_file_metadata_t);
		entry->filename = strdup(buf);
		entry->meta_length = PTS_FILE_METADATA_SIZE + strlen(entry->filename);
		entry->type = type;
		entry->filesize = filesize;
		entry->create_time = create_time_t;
		entry->last_modify_time = modify_time_t;
		entry->last_access_time = access_time_t;
		entry->owner_id = owner_id;
		entry->group_id = group_id;
		
		this->metadata->add(this->metadata, entry);
	}
	status = SUCCESS;

end:
	reader->destroy(reader);
	return status;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_file_meta_t *this)
{
	this->metadata->destroy(this->metadata);
	free(this->value.ptr);
	free(this);
}

METHOD(tcg_pts_attr_file_meta_t, get_metadata, pts_file_meta_t*,
	private_tcg_pts_attr_file_meta_t *this)
{
	return this->metadata;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_unix_file_meta_create(pts_file_meta_t *metadata)
{
	private_tcg_pts_attr_file_meta_t *this;

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
			.get_metadata = _get_metadata,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_UNIX_FILE_META,
		.metadata = metadata,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_unix_file_meta_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_file_meta_t *this;

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
			.get_metadata = _get_metadata,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_UNIX_FILE_META,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
