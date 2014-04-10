/*
 * Copyright (C) 2013-2014 Andreas Steffen
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

#include "tcg_swid_attr_tag_id_inv.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/debug.h>


typedef struct private_tcg_swid_attr_tag_id_inv_t private_tcg_swid_attr_tag_id_inv_t;

/**
 * SWID Tag Identifier Inventory
 * see section 4.8 of TCG TNC SWID Message and Attributes for IF-M
 *
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Reserved    |                 Tag ID Count                  | 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Request ID Copy                        | 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           EID Epoch                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Last EID                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |       Tag Creator Length      | Tag Creator (variable length) |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Unique Software ID Length  |Unique Software ID (var length)|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Tag File Path Length     |  Tag File Path (var. length)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define TCG_SWID_TAG_ID_INV_RESERVED	0x00

/**
 * Private data of an tcg_swid_attr_tag_id_inv_t object.
 */
struct private_tcg_swid_attr_tag_id_inv_t {

	/**
	 * Public members of tcg_swid_attr_tag_id_inv_t
	 */
	tcg_swid_attr_tag_id_inv_t public;

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
	 * Request ID
	 */
	uint32_t request_id;

	/**
	 * Event ID Epoch
	 */
	uint32_t eid_epoch;

	/**
	 * Last Event ID
	 */
	uint32_t last_eid;

	/**
	 * SWID Tag ID Inventory
	 */
	swid_inventory_t *inventory;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(pa_tnc_attr_t, get_type, pen_type_t,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_swid_attr_tag_id_inv_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	bio_writer_t *writer;
	swid_tag_id_t *tag_id;
	chunk_t tag_creator, unique_sw_id, tag_file_path;
	enumerator_t *enumerator;

	if (this->value.ptr)
	{
		return;
	}

	writer = bio_writer_create(TCG_SWID_TAG_ID_INV_MIN_SIZE);
	writer->write_uint8 (writer, TCG_SWID_TAG_ID_INV_RESERVED);
	writer->write_uint24(writer, this->inventory->get_count(this->inventory));
	writer->write_uint32(writer, this->request_id);
	writer->write_uint32(writer, this->eid_epoch);
	writer->write_uint32(writer, this->last_eid);

	enumerator = this->inventory->create_enumerator(this->inventory);
	while (enumerator->enumerate(enumerator, &tag_id))
	{
		tag_creator = tag_id->get_tag_creator(tag_id);
		unique_sw_id = tag_id->get_unique_sw_id(tag_id, &tag_file_path);
		writer->write_data16(writer, tag_creator);
		writer->write_data16(writer, unique_sw_id);
		writer->write_data16(writer, tag_file_path);
	}
	enumerator->destroy(enumerator);

	this->value = writer->extract_buf(writer);
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_swid_attr_tag_id_inv_t *this, uint32_t *offset)
{
	bio_reader_t *reader;
	uint32_t tag_id_count;
	uint8_t reserved;
	chunk_t tag_creator, unique_sw_id, tag_file_path;
	swid_tag_id_t *tag_id;

	if (this->value.len < TCG_SWID_TAG_ID_INV_MIN_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for SWID Tag Identifier Inventory");
		*offset = 0;
		return FAILED;
	}

	reader = bio_reader_create(this->value);
	reader->read_uint8 (reader, &reserved);
	reader->read_uint24(reader, &tag_id_count);
	reader->read_uint32(reader, &this->request_id);
	reader->read_uint32(reader, &this->eid_epoch);
	reader->read_uint32(reader, &this->last_eid);
	*offset = TCG_SWID_TAG_ID_INV_MIN_SIZE;

	while (tag_id_count--)
	{
		if (!reader->read_data16(reader, &tag_creator))
		{
			DBG1(DBG_TNC, "insufficient data for Tag Creator field");
			return FAILED;
		}
		*offset += 2 + tag_creator.len;

		if (!reader->read_data16(reader, &unique_sw_id))
		{
			DBG1(DBG_TNC, "insufficient data for Unique Software ID");
			return FAILED;
		}
		*offset += 2 + unique_sw_id.len;
		
		if (!reader->read_data16(reader, &tag_file_path))
		{
			DBG1(DBG_TNC, "insufficient data for Tag File Path");
			return FAILED;
		}
		*offset += 2 + tag_file_path.len;

		tag_id = swid_tag_id_create(tag_creator, unique_sw_id, tag_file_path);
		this->inventory->add(this->inventory, tag_id);
	}
	reader->destroy(reader);

	return SUCCESS;
}

METHOD(pa_tnc_attr_t, get_ref, pa_tnc_attr_t*,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	ref_get(&this->ref);
	return &this->public.pa_tnc_attribute;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	if (ref_put(&this->ref))
	{
		this->inventory->destroy(this->inventory);
		free(this->value.ptr);
		free(this);
	}
}

METHOD(tcg_swid_attr_tag_id_inv_t, add, void,
	private_tcg_swid_attr_tag_id_inv_t *this, swid_tag_id_t *tag_id)
{
	this->inventory->add(this->inventory, tag_id);
}

METHOD(tcg_swid_attr_tag_id_inv_t, get_request_id, uint32_t,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	return this->request_id;
}

METHOD(tcg_swid_attr_tag_id_inv_t, get_last_eid, uint32_t,
	private_tcg_swid_attr_tag_id_inv_t *this, uint32_t *eid_epoch)
{
	if (eid_epoch)
	{
		*eid_epoch = this->eid_epoch;
	}
	return this->last_eid;
}

METHOD(tcg_swid_attr_tag_id_inv_t, get_inventory, swid_inventory_t*,
	private_tcg_swid_attr_tag_id_inv_t *this)
{
	return this->inventory;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_swid_attr_tag_id_inv_create(uint32_t request_id,
											   uint32_t eid_epoch,
											   uint32_t eid)
{
	private_tcg_swid_attr_tag_id_inv_t *this;

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
			.add = _add,
			.get_request_id = _get_request_id,
			.get_last_eid = _get_last_eid,
			.get_inventory = _get_inventory,
		},
		.type = { PEN_TCG, TCG_SWID_TAG_ID_INVENTORY },
		.request_id = request_id,
		.eid_epoch = eid_epoch,
		.last_eid = eid,
		.inventory = swid_inventory_create(FALSE),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_swid_attr_tag_id_inv_create_from_data(chunk_t data)
{
	private_tcg_swid_attr_tag_id_inv_t *this;

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
			.add = _add,
			.get_request_id = _get_request_id,
			.get_last_eid = _get_last_eid,
			.get_inventory = _get_inventory,
		},
		.type = { PEN_TCG, TCG_SWID_TAG_ID_INVENTORY },
		.value = chunk_clone(data),
		.inventory = swid_inventory_create(FALSE),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}
