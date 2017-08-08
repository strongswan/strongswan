/*
 * Copyright (C) 2013-2017 Andreas Steffen
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
#include "swid_gen/swid_gen.h"

#include <collections/linked_list.h>
#include <utils/lexparser.h>
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

static status_t generate_tags(private_swid_inventory_t *this,
							  swid_inventory_t *targets, bool pretty, bool full)
{
	swid_gen_t *swid_gen;
	swid_tag_t *tag;
	swid_tag_id_t *tag_id;
	enumerator_t *enumerator;
	status_t status = SUCCESS;
	chunk_t out;

	swid_gen = swid_gen_create();

	if (targets->get_count(targets) == 0)
	{
		DBG2(DBG_IMC, "SWID tag%s generation by package manager",
					   this->full_tags ? "" : " ID");

		enumerator = swid_gen->create_tag_enumerator(swid_gen, !this->full_tags,
													 full, pretty);
		if (enumerator)
		{
			while (enumerator->enumerate(enumerator, &out))
			{
				if (this->full_tags)
				{
					chunk_t swid_tag = out;

					tag = swid_tag_create(swid_tag, chunk_empty);
					this->list->insert_last(this->list, tag);
				}
				else
				{
					chunk_t tag_creator, sw_id = out;

					if (extract_token_str(&tag_creator, "__", &sw_id))
					{
						tag_id = swid_tag_id_create(tag_creator, sw_id,
													chunk_empty);
						this->list->insert_last(this->list, tag_id);
					}
					else
					{
						DBG1(DBG_IMC, "separation of regid from unique "
									  "software ID failed");
						status = FAILED;
						chunk_free(&out);
						break;
					}
				}
				chunk_free(&out);
			}
			enumerator->destroy(enumerator);
		}
		else
		{
			status = NOT_SUPPORTED;
		}
	}
	else if (this->full_tags)
	{
		DBG2(DBG_IMC, "targeted SWID tag generation");

		enumerator = targets->create_enumerator(targets);
		while (enumerator->enumerate(enumerator, &tag_id))
		{
			char software_id[BUF_LEN], *swid_tag;
			chunk_t tag_creator, sw_id;

			/* Construct software ID from tag creator and unique software ID */
			tag_creator  = tag_id->get_tag_creator(tag_id);
			sw_id = tag_id->get_unique_sw_id(tag_id, NULL);
			snprintf(software_id, BUF_LEN, "%.*s__%.*s",
					 (int)tag_creator.len, tag_creator.ptr,
					 (int)sw_id.len, sw_id.ptr);

			swid_tag = swid_gen->generate_tag(swid_gen, software_id, NULL, NULL,
										 full, pretty);
			if (swid_tag)
			{
				tag = swid_tag_create(chunk_from_str(swid_tag), chunk_empty);
				this->list->insert_last(this->list, tag);
				free(swid_tag);
			}
		}
		enumerator->destroy(enumerator);
	}
	swid_gen->destroy(swid_gen);

	return status;
}

static bool collect_tags(private_swid_inventory_t *this, char *pathname,
						 swid_inventory_t *targets, bool is_swidtag_dir)
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
	if (is_swidtag_dir)
	{
			DBG2(DBG_IMC, "entering %s", pathname);
	}

	while (enumerator->enumerate(enumerator, &rel_name, &abs_name, &st))
	{
		char *separator, *suffix;
		chunk_t tag_creator;
		chunk_t unique_sw_id = chunk_empty, tag_file_path = chunk_empty;

		if (S_ISDIR(st.st_mode))
		{
			if (!collect_tags(this, abs_name, targets, is_swidtag_dir ||
							  streq(rel_name, "swidtag")))
			{
				goto end;
			}
			continue;
		}
		if (!is_swidtag_dir)
		{
			continue;
		}

		/* found a swidtag file? */
		suffix = strstr(rel_name, ".swidtag");
		if (!suffix)
		{
			continue;
		}

		/* parse the swidtag filename into its components */
		separator = strstr(rel_name, "__");
		if (!separator)
		{
			DBG1(DBG_IMC, "  %s", rel_name);
			DBG1(DBG_IMC, "  '__' separator not found");
			goto end;
		}
		tag_creator = chunk_create(rel_name, separator-rel_name);

		unique_sw_id = chunk_create(separator+2, suffix-separator-2);
		tag_file_path = chunk_from_str(abs_name);

		/* In case of a targeted request */
		if (targets->get_count(targets))
		{
			chunk_t target_unique_sw_id, target_tag_creator;
			enumerator_t *target_enumerator;
			swid_tag_id_t *tag_id;
			bool match = FALSE;

			target_enumerator = targets->create_enumerator(targets);
			while (target_enumerator->enumerate(target_enumerator, &tag_id))
			{
				target_unique_sw_id = tag_id->get_unique_sw_id(tag_id, NULL);
				target_tag_creator  = tag_id->get_tag_creator(tag_id);

				if (chunk_equals(target_unique_sw_id, unique_sw_id) &&
				    chunk_equals(target_tag_creator, tag_creator))
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

			tag = swid_tag_create(*xml_tag, tag_file_path);
			this->list->insert_last(this->list, tag);
			chunk_unmap(xml_tag);
		}
		else
		{
			swid_tag_id_t *tag_id;

			tag_id = swid_tag_id_create(tag_creator, unique_sw_id, tag_file_path);
			this->list->insert_last(this->list, tag_id);
		}
	}
	success = TRUE;

end:
	enumerator->destroy(enumerator);
	if (is_swidtag_dir)
	{
		DBG2(DBG_IMC, "leaving %s", pathname);
	}

	return success;
}

METHOD(swid_inventory_t, collect, bool,
	private_swid_inventory_t *this, char *directory, swid_inventory_t *targets,
	bool pretty, bool full)
{
	/**
	 * Tags are generated by a package manager
	 */
	generate_tags(this, targets, pretty, full);

	/**
	 * Collect swidtag files by iteratively entering all directories in
	 * the tree under the "directory" path.
	 */
	return collect_tags(this, directory, targets, FALSE);
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
