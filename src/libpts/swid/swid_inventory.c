/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "swid_inventory.h"
#include "swid_tag.h"
#include "swid_tag_id.h"

#include <collections/linked_list.h>
#include <utils/debug.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

typedef struct private_swid_inventory_t private_swid_inventory_t;

/**
 * Private data of a swid_inventory_t object.
 *
 */
struct private_swid_inventory_t {

	/**
	 * Public swid_inventory_t interface.
	 */
	swid_inventory_t public;

	/**
	 * Full SWID tags or just SWID tag IDs
	 */
	bool full_tags;

	/**
	 * List of SWID tags or tag IDs
	 */
	linked_list_t *list;
};

static bool collect_tags(private_swid_inventory_t *this, char *pathname,
						 swid_inventory_t *targets)
{
	char *rel_name, *abs_name;
	struct stat st;
	bool success = FALSE;
	enumerator_t *enumerator;

	enumerator = enumerator_create_directory(pathname);
	if (!enumerator)
	{
		DBG1(DBG_IMC, "directory '%s' can not be opened, %s",
			 pathname, strerror(errno));
		return FALSE;
	}
	DBG2(DBG_IMC, "entering %s", pathname);

	while (enumerator->enumerate(enumerator, &rel_name, &abs_name, &st))
	{
		char * start, *stop;
		chunk_t tag_creator;
		chunk_t unique_sw_id = chunk_empty, unique_seq_id = chunk_empty;
		if (!strstr(rel_name, "regid."))
		{
			continue;
		}
		if (S_ISDIR(st.st_mode))
		{
			/* In case of a targeted request */
			if (targets->get_count(targets))
			{
				enumerator_t *target_enumerator;
				swid_tag_id_t *tag_id;
				bool match = FALSE;

				target_enumerator = targets->create_enumerator(targets);
				while (target_enumerator->enumerate(target_enumerator, &tag_id))
				{
					if (chunk_equals(tag_id->get_tag_creator(tag_id),
						chunk_from_str(rel_name)))
					{
						match = TRUE;
						break;
					}
				}
				target_enumerator->destroy(target_enumerator);

				if (!match)
				{
					continue;
				}
			}

			if (!collect_tags(this, abs_name, targets))
			{
				goto end;
			}
			continue;
		}

		/* parse the regid filename into its components */
		start = rel_name;
		stop = strchr(start, '_');
		if (!stop)
		{
			DBG1(DBG_IMC, "  %s", rel_name);
			DBG1(DBG_IMC, "  '_' separator not found");
			goto end;
		}
		tag_creator = chunk_create(start, stop-start);

		start = stop + 1;
		stop = strchr(start, '_');
		if (stop)
		{
			unique_sw_id = chunk_create(start, stop-start);
			start = stop + 1;
		}

		stop = strstr(start, ".swidtag");
		if (!stop)
		{
			DBG1(DBG_IMC, "  %s", rel_name);
			DBG1(DBG_IMC, "  swidtag postfix not found");
			goto end;
		}
		if (unique_sw_id.ptr)
		{
			unique_seq_id = chunk_create(start, stop-start);
		}
		else
		{
			unique_sw_id = chunk_create(start, stop-start);
		}

		/* In case of a targeted request */
		if (targets->get_count(targets))
		{
			enumerator_t *target_enumerator;
			swid_tag_id_t *tag_id;
			bool match = FALSE;

			target_enumerator = targets->create_enumerator(targets);
			while (target_enumerator->enumerate(target_enumerator, &tag_id))
			{
				if (chunk_equals(tag_id->get_unique_sw_id(tag_id, NULL),
								 unique_sw_id) &&
					chunk_equals(tag_id->get_tag_creator(tag_id),
								 tag_creator))
				{
					match = TRUE;
					break;
				}
			}
			target_enumerator->destroy(target_enumerator);

			if (!match)
			{
				continue;
			}
		}
		DBG2(DBG_IMC, "  %s", rel_name);

		if (this->full_tags)
		{
			swid_tag_t *tag;
			chunk_t *xml_tag;

			xml_tag = chunk_map(abs_name, FALSE);
			if (!xml_tag)
			{
				DBG1(DBG_IMC, "  opening '%s' failed: %s", abs_name,
					 strerror(errno));
				goto end;
			}

			tag = swid_tag_create(*xml_tag, unique_seq_id);
			this->list->insert_last(this->list, tag);
			chunk_unmap(xml_tag);
		}
		else
		{
			swid_tag_id_t *tag_id;

			tag_id = swid_tag_id_create(tag_creator, unique_sw_id, unique_seq_id);
			this->list->insert_last(this->list, tag_id);
		}

	}
	success = TRUE;

end:
	enumerator->destroy(enumerator);
	DBG2(DBG_IMC, "leaving %s", pathname);

	return success;
}

METHOD(swid_inventory_t, collect, bool,
	private_swid_inventory_t *this, char *directory, swid_inventory_t *targets)
{
	return collect_tags(this, directory, targets);
}

METHOD(swid_inventory_t, add, void,
	private_swid_inventory_t *this, void *item)
{
	this->list->insert_last(this->list, item);
}

METHOD(swid_inventory_t, get_count, int,
	private_swid_inventory_t *this)
{
	return this->list->get_count(this->list);
}

METHOD(swid_inventory_t, create_enumerator, enumerator_t*,
	private_swid_inventory_t *this)
{
	return this->list->create_enumerator(this->list);
}

METHOD(swid_inventory_t, destroy, void,
	private_swid_inventory_t *this)
{
	if (this->full_tags)
	{
		this->list->destroy_offset(this->list, offsetof(swid_tag_t, destroy));
	}
	else
	{
		this->list->destroy_offset(this->list, offsetof(swid_tag_id_t, destroy));
	}
	free(this);
}

/**
 * See header
 */
swid_inventory_t *swid_inventory_create(bool full_tags)
{
	private_swid_inventory_t *this;

	INIT(this,
		.public = {
			.collect = _collect,
			.add = _add,
			.get_count = _get_count,
			.create_enumerator = _create_enumerator,
			.destroy = _destroy,
		},
		.full_tags = full_tags,
		.list = linked_list_create(),
	);

	return &this->public;
}
