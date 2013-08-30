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
#include <sys/mman.h>
#include <libgen.h>
#include <errno.h>

typedef struct private_swid_inventory_t private_swid_inventory_t;

#define SWID_TAG_DIRECTORY	"/usr/share"

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

static bool collect_tags(private_swid_inventory_t *this, char *pathname)
{
	char *rel_name, *abs_name;
	struct stat st;
	bool success = FALSE;
	enumerator_t *enumerator;

	enumerator = enumerator_create_directory(pathname);
	if (!enumerator)
	{
		DBG1(DBG_IMV, "directory '%s' can not be opened, %s",
			 pathname, strerror(errno));
		return FALSE;
	}
	DBG2(DBG_IMV, "entering %s", pathname);
	
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
			if (!collect_tags(this, abs_name))
			{
				goto end;
			}
			continue;
		}
		DBG2(DBG_IMV, "  %s", rel_name);

		/* parse the regid filename into its components */
		start = rel_name;
		stop = strchr(start, '_');
		if (!stop)
		{
			DBG1(DBG_IMV, "  '_' separator not found");
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
			DBG1(DBG_IMV, "  swidtag postfix not found");
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

		if (this->full_tags)
		{
			swid_tag_t *tag;
			chunk_t xml_tag;
			struct stat sb;
			void *addr;
			int fd;

			fd = open(abs_name, O_RDONLY);
			if (fd == -1)
			{
				DBG1(DBG_IMV, "  opening '%s' failed: %s", abs_name,
					 strerror(errno));
				goto end;
			}

			if (fstat(fd, &sb) == -1)
			{
				DBG1(DBG_IMV, "  getting file size of '%s' failed: %s", abs_name,
			 		 strerror(errno));
				close(fd);
				goto end;
			}

			addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
			if (addr == MAP_FAILED)
			{
				DBG1(DBG_IMV, "  mapping '%s' failed: %s", abs_name,
					 strerror(errno));
				close(fd);
				goto end;
			}
			xml_tag = chunk_create(addr, sb.st_size);

			tag = swid_tag_create(xml_tag, unique_seq_id);
			this->list->insert_last(this->list, tag);
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
	DBG2(DBG_IMV, "leaving %s", pathname);

	return success;
}

METHOD(swid_inventory_t, collect, bool,
	private_swid_inventory_t *this)
{
	return collect_tags(this, SWID_TAG_DIRECTORY);
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


