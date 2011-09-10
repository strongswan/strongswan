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

#include "pts_file_meas.h"

#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_pts_file_meas_t private_pts_file_meas_t;

/**
 * Private data of a pts_file_meas_t object.
 *
 */
struct private_pts_file_meas_t {

	/**
	 * Public pts_file_meas_t interface.
	 */
	pts_file_meas_t public;

	/**
	 * ID of PTS File Measurement Request
	 */
	u_int16_t request_id;

	/**
	 * List of File Measurements
	 */
	linked_list_t *list;
};

typedef struct entry_t entry_t;

/**
 * PTS File Measurement entry
 */
struct entry_t {
	char	 *filename;
	chunk_t  measurement;
};

/**
 * Free an entry_t object
 */
static void free_entry(entry_t *entry)
{
	if (entry)
	{
		free(entry->filename);
		free(entry->measurement.ptr);
		free(entry);
	}
}

METHOD(pts_file_meas_t, get_request_id, u_int16_t,
	private_pts_file_meas_t *this)
{
	return this->request_id;
}

METHOD(pts_file_meas_t, get_file_count, int,
	private_pts_file_meas_t *this)
{
	return this->list->get_count(this->list);
}

METHOD(pts_file_meas_t, add, void,
	private_pts_file_meas_t *this, char *filename, chunk_t measurement)
{
	entry_t *entry;

	entry = malloc_thing(entry_t);
	entry->filename = strdup(filename);
	entry->measurement = chunk_clone(measurement);

	this->list->insert_last(this->list, entry);
}

/**
 * Enumerate file measurement entries
 */
static bool entry_filter(void *null, entry_t **entry, char **filename,
						 void *i2, chunk_t *measurement)
{
	*filename = (*entry)->filename;
	*measurement = (*entry)->measurement;
	return TRUE;
}

METHOD(pts_file_meas_t, create_enumerator, enumerator_t*,
	private_pts_file_meas_t *this)
{
	return enumerator_create_filter(this->list->create_enumerator(this->list),
								   (void*)entry_filter, NULL, NULL);
}

METHOD(pts_file_meas_t, verify, bool,
	private_pts_file_meas_t *this, enumerator_t *e_hash, bool is_dir)
{
	char *filename;
	chunk_t measurement;
	entry_t *entry;
	enumerator_t *enumerator;
	bool found, success = TRUE;

	while (e_hash->enumerate(e_hash, &filename, &measurement))
	{
		found = FALSE;

		enumerator = this->list->create_enumerator(this->list);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (!is_dir || streq(filename, entry->filename))
			{
				found = TRUE;
				break;
			}
		}
		enumerator->destroy(enumerator);
		
		if (!found)
		{
			DBG1(DBG_PTS, "  no measurement found for '%s'", filename);
			success = FALSE;
			continue;
		}
		if (chunk_equals(measurement, entry->measurement))
		{
			DBG2(DBG_PTS, "  %#B for '%s' is ok", &measurement, filename);
		}
		else
		{
			DBG1(DBG_PTS, "  %#B for '%s' is incorrect", &measurement, filename);
			success = FALSE;
		}
		if (!is_dir)
		{
			break;
		}
	}
	return success;	
}

METHOD(pts_file_meas_t, destroy, void,
	private_pts_file_meas_t *this)
{
	this->list->destroy_function(this->list, (void *)free_entry);
	free(this);
}

/**
 * See header
 */
pts_file_meas_t *pts_file_meas_create(u_int16_t request_id)
{
	private_pts_file_meas_t *this;

	INIT(this,
		.public = {
			.get_request_id = _get_request_id,
			.get_file_count = _get_file_count,
			.add = _add,
			.create_enumerator = _create_enumerator,
			.verify = _verify,
			.destroy = _destroy,
		},
		.request_id = request_id,
		.list = linked_list_create(),
	);

	return &this->public;
}

