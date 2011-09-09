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

#include "pts_file_meta.h"

#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_pts_file_meta_t private_pts_file_meta_t;

/**
 * Private data of a pts_file_meta_t object.
 *
 */
struct private_pts_file_meta_t {

	/**
	 * Public pts_file_meta_t interface.
	 */
	pts_file_meta_t public;

	/**
	 * List of File Metadata
	 */
	linked_list_t *list;
};

/**
 * Free an pts_file_metadata_t object
 */
static void free_entry(pts_file_metadata_t *entry)
{
	if (entry)
	{
		free(entry->filename);
		free(entry);
	}
}

METHOD(pts_file_meta_t, get_file_count, int,
	private_pts_file_meta_t *this)
{
	return this->list->get_count(this->list);
}

METHOD(pts_file_meta_t, add, void,
	private_pts_file_meta_t *this, char *filename, pts_file_type_t type,
	u_int64_t filesize, time_t create_time, time_t last_modify_time, time_t last_access_time,
	u_int64_t owner_id, u_int64_t group_id)
{
	pts_file_metadata_t *entry;

	entry = malloc_thing(pts_file_metadata_t);
	
	entry->filename = strdup(filename);
 	entry->meta_length = PTS_FILE_METADATA_SIZE + strlen(entry->filename);
	entry->type = type;
	entry->filesize = filesize;
	entry->create_time = create_time;
	entry->last_modify_time = last_modify_time;
	entry->last_access_time = last_access_time;
	entry->owner_id = owner_id;
	entry->group_id = group_id;
	
	this->list->insert_last(this->list, entry);
}

/**
 * Enumerate file metadata entries
 */
static bool entry_filter(void *null, pts_file_metadata_t **entry,
							char **filename,  void *i2, u_int16_t *meta_length, void *i3,
							pts_file_type_t *type, void *i4, u_int64_t *filesize, void *i5,
							time_t *create_time, void *i6, time_t *last_modify_time, void *i7,
							time_t *last_access_time, void *i8, u_int64_t *owner_id, void *i9,
							u_int64_t *group_id)
{
	*filename = (*entry)->filename;
	*meta_length = (*entry)->meta_length;
	*type = (*entry)->type;
	*filesize = (*entry)->filesize;
	*create_time = (*entry)->create_time;
	*last_modify_time = (*entry)->last_modify_time;
	*last_access_time = (*entry)->last_access_time;
	*owner_id = (*entry)->owner_id;
	*group_id = (*entry)->group_id;
	return TRUE;
}

METHOD(pts_file_meta_t, create_enumerator, enumerator_t*,
	private_pts_file_meta_t *this)
{
	return enumerator_create_filter(this->list->create_enumerator(this->list),
								   (void*)entry_filter, NULL, NULL);
}

METHOD(pts_file_meta_t, destroy, void,
	private_pts_file_meta_t *this)
{
	this->list->destroy_function(this->list, (void *)free_entry);
	free(this);
}

/**
 * See header
 */
pts_file_meta_t *pts_file_meta_create()
{
	private_pts_file_meta_t *this;

	INIT(this,
		.public = {
			.get_file_count = _get_file_count,
			.add = _add,
			.create_enumerator = _create_enumerator,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
	);

	return &this->public;
}

