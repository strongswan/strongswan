/*
 * Copyright (C) 2011 Andreas Steffen
 *
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

#include "pa_tnc_attr_manager.h"

#include <collections/linked_list.h>
#include <utils/debug.h>

typedef struct private_pa_tnc_attr_manager_t private_pa_tnc_attr_manager_t;
typedef struct entry_t entry_t;

struct entry_t {
	pen_t vendor_id;
	enum_name_t *attr_names;
	pa_tnc_attr_create_t attr_create;
};

/**
 * Private data of a pa_tnc_attr_manager_t object.
 *
 */
struct private_pa_tnc_attr_manager_t {

	/**
	 * Public pa_tnc_attr_manager_t interface.
	 */
	pa_tnc_attr_manager_t public;

	/**
	 * List of PA-TNC vendor attributes
	 */
	linked_list_t *list;
};

METHOD(pa_tnc_attr_manager_t, add_vendor, void,
	private_pa_tnc_attr_manager_t *this, pen_t vendor_id,
	pa_tnc_attr_create_t attr_create, enum_name_t *attr_names)
{
	entry_t *entry;

	entry = malloc_thing(entry_t);
	entry->vendor_id = vendor_id;
	entry->attr_create = attr_create;
	entry->attr_names = attr_names;

	this->list->insert_last(this->list, entry);
	DBG2(DBG_TNC, "added %N attributes", pen_names, vendor_id);
}

METHOD(pa_tnc_attr_manager_t, remove_vendor, void,
	private_pa_tnc_attr_manager_t *this, pen_t vendor_id)
{
	enumerator_t *enumerator;
	entry_t *entry;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->vendor_id == vendor_id)
		{
			this->list->remove_at(this->list, enumerator);
			free(entry);
			DBG2(DBG_TNC, "removed %N attributes", pen_names, vendor_id);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(pa_tnc_attr_manager_t, get_names, enum_name_t*,
	private_pa_tnc_attr_manager_t *this, pen_t vendor_id)
{
	enumerator_t *enumerator;
	entry_t *entry;
	enum_name_t *attr_names = NULL;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->vendor_id == vendor_id)
		{
			attr_names = entry->attr_names;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return attr_names;
}

METHOD(pa_tnc_attr_manager_t, create, pa_tnc_attr_t*,
	private_pa_tnc_attr_manager_t *this, pen_t vendor_id, u_int32_t type,
	chunk_t value)
{
	enumerator_t *enumerator;
	entry_t *entry;
	pa_tnc_attr_t *attr = NULL;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->vendor_id == vendor_id)
		{
			if (entry->attr_create)
			{
				attr = entry->attr_create(type, value);
			}
			break;
		}
	}
	enumerator->destroy(enumerator);

	return attr;
}

METHOD(pa_tnc_attr_manager_t, destroy, void,
	private_pa_tnc_attr_manager_t *this)
{
	this->list->destroy_function(this->list, free);
	free(this);
}

/**
 * See header
 */
pa_tnc_attr_manager_t *pa_tnc_attr_manager_create(void)
{
	private_pa_tnc_attr_manager_t *this;

	INIT(this,
		.public = {
			.add_vendor = _add_vendor,
			.remove_vendor = _remove_vendor,
			.get_names = _get_names,
			.create = _create,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
	);

	return &this->public;
}

