/*
 * Copyright (C) 2017 Andreas Steffen
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

#define _GNU_SOURCE
#include <stdio.h>

#include "sw_collector_info.h"

#include <library.h>
#include <utils/lexparser.h>

typedef struct private_sw_collector_info_t private_sw_collector_info_t;

/**
 * Private data of an sw_collector_info_t object.
 */
struct private_sw_collector_info_t {

	/**
	 * Public members of sw_collector_info_state_t
	 */
	sw_collector_info_t public;

	/**
	 * tagCreator
	 */
	char *tag_creator;

	/**
	 * OS string 'Name_Version-Arch'
	 */
	char *os;

	/**
	 * Product string 'Name Version Arch'
	 */
	char *product;

	/**
	 * OS info about endpoint
	 */
	imc_os_info_t *os_info;

};

/**
 * Replaces invalid character by a valid one
 */
static void sanitize_uri(char *uri, char a, char b)
{
	char *pos = uri;

	while (TRUE)
	{
		pos = strchr(pos, a);
		if (!pos)
		{
			break;
		}
		*pos = b;
		pos++;
	}
}

METHOD(sw_collector_info_t, get_os_type, os_type_t,
	private_sw_collector_info_t *this)
{
	return this->os_info->get_type(this->os_info);
}

METHOD(sw_collector_info_t, get_os, char*,
	private_sw_collector_info_t *this, char **product)
{
	if (product)
	{
		*product = this->product;
	}
	return this->os;
}

METHOD(sw_collector_info_t, create_sw_id, char*,
	private_sw_collector_info_t *this, char *package, char *version)
{
	char *pos, *sw_id;
	size_t len;

	/* Remove architecture from package name */
	pos = strchr(package, ':');
	len = pos ? (pos - package) : strlen(package);

	/* Build software identifier */
	if (asprintf(&sw_id, "%s__%s-%.*s%s%s", this->tag_creator, this->os, len,
				 package, strlen(version) ? "-" : "", version) == -1)
	{
		return NULL;
	}
	sanitize_uri(sw_id, ':', '~');
	sanitize_uri(sw_id, '+', '~');

	return sw_id;
}

METHOD(sw_collector_info_t, destroy, void,
	private_sw_collector_info_t *this)
{
	this->os_info->destroy(this->os_info);
	free(this->os);
	free(this->product);
	free(this->tag_creator);
	free(this);
}

/**
 * Described in header.
 */
sw_collector_info_t *sw_collector_info_create(char *tag_creator)
{
	private_sw_collector_info_t *this;
	chunk_t os_name, os_version, os_arch;

	INIT(this,
		.public = {
			.get_os_type = _get_os_type,
			.get_os = _get_os,
			.create_sw_id = _create_sw_id,
			.destroy = _destroy,
		},
		.os_info = imc_os_info_create(),
		.tag_creator = strdup(tag_creator),
	);

	os_name = this->os_info->get_name(this->os_info);
	os_arch = this->os_info->get_version(this->os_info);

	/* get_version() returns version followed by arch */ 
	if (!extract_token(&os_version, ' ', &os_arch))
	{
		DBG1(DBG_IMC, "separation of OS version from arch failed");
		destroy(this);
		return NULL;
	}

	/* construct OS string */
	if (asprintf(&this->os, "%.*s_%.*s-%.*s", os_name.len, os_name.ptr,
											  os_version.len, os_version.ptr,
		 									  os_arch.len, os_arch.ptr) == -1)
	{
		DBG1(DBG_IMC, "constructon of OS string failed");
		destroy(this);
		return NULL;
	}

	/* construct product string */
	if (asprintf(&this->product, "%.*s %.*s %.*s", os_name.len, os_name.ptr,
											  os_version.len, os_version.ptr,
											  os_arch.len, os_arch.ptr) == -1)
	{
		DBG1(DBG_IMC, "constructon of product string failed");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
