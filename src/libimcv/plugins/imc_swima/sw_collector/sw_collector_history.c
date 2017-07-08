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
#include <time.h>

#include "sw_collector_history.h"

#include "imc/imc_os_info.h"
#include "swima/swima_event.h"

typedef struct private_sw_collector_history_t private_sw_collector_history_t;

/**
 * Private data of an sw_collector_history_t object.
 */
struct private_sw_collector_history_t {

	/**
	 * Public members of sw_collector_history_state_t
	 */
	sw_collector_history_t public;

	/**
	 * tagCreator
	 */
	char *tag_creator;

	/**
	 * OS string 'name_version-arch'
	 */
	char *os;

	/**
	 * Product string 'name version arch'
	 */
	char *product;

	/**
	 * OS info about endpoint
	 */
	imc_os_info_t *os_info;

	/**
	 * Software Event Source Number
	 */
	uint8_t source;

	/**
	 * Reference to collector database
	 */
	sw_collector_db_t *db;

};

METHOD(sw_collector_history_t, get_os, char*,
	private_sw_collector_history_t *this, char **product)
{
	if (product)
	{
		*product = this->product;
	}
	return this->os;
}

/**
 * Define auxiliary package_t list item object
 */
typedef struct package_t package_t;

struct package_t {
	char *package;
	char *version;
	char *old_version;
	char *sw_id;
	char *old_sw_id;
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

/**
 * Create software identifier
 */
char* create_sw_id(char *tag_creator, char *os, char *package, char *version)
{
	char *pos, *sw_id;
	size_t len;

	/* Remove architecture from package name */
	pos = strchr(package, ':');
	len = pos ? (pos - package) : strlen(package);

	/* Build software identifier */
	if (asprintf(&sw_id, "%s__%s-%.*s%s%s", tag_creator, os, len, package,
				 strlen(version) ? "-" : "", version) == -1)
	{
		return NULL;
	}
	sanitize_uri(sw_id, ':', '~');
	sanitize_uri(sw_id, '+', '~');

	return sw_id;
}

/**
 * Create package_t list item object
 */
static package_t* create_package(char* tag_creator, char *os, chunk_t package,
								 chunk_t version, chunk_t old_version)
{
	package_t *this;

	INIT(this,
		.package = strndup(package.ptr, package.len),
		.version = strndup(version.ptr, version.len),
		.old_version = strndup(old_version.ptr, old_version.len),
	)

	this->sw_id = create_sw_id(tag_creator, os, this->package, this->version);
	if (old_version.len)
	{
		this->old_sw_id = create_sw_id(tag_creator, os, this->package,
									   this->old_version);
	}

	return this;
}

/**
 * Free package_t list item object
 */
static void free_package(package_t *this)
{
	if (this)
	{
		free(this->package);
		free(this->version);
		free(this->old_version);
		free(this->sw_id);
		free(this->old_sw_id);
		free(this);
	}
}

/**
 * Extract and parse a single package item
 */
static package_t* extract_package(chunk_t item, char *tag_creator, char *os,
								  sw_collector_history_op_t op)
{
	chunk_t package, version, old_version;
	package_t *p;

	/* extract package name */
	if (!extract_token(&package, ' ', &item))
	{
		fprintf(stderr, "version not found.\n");
		return NULL;
	}
	item = chunk_skip(item, 1);

	/* extract versions */
	version = old_version = chunk_empty;

	if (item.len > 0)
	{
		if (extract_token(&version, ',', &item))
		{
			eat_whitespace(&item);
			if (!match("automatic", &item))
			{
				old_version = version;
				version = item;
			}
		}
		else
		{
			version = item;
		}
	}
	p = create_package(tag_creator, os, package, version, old_version);

	/* generate log entry */
	if (op == SW_OP_UPGRADE)
	{
		DBG2(DBG_IMC, "    %s (%s, %s)", p->package, p->old_version, p->version);
		DBG2(DBG_IMC, "      +%s", p->sw_id);
		DBG2(DBG_IMC, "      -%s", p->old_sw_id);
	}
	else
	{
		DBG2(DBG_IMC, "    %s (%s)", p->package, p->version);
		DBG2(DBG_IMC, "      %s%s", (op == SW_OP_INSTALL) ? "+" : "-", p->sw_id);
	}

	return p;
}

METHOD(sw_collector_history_t, extract_timestamp, bool,
	private_sw_collector_history_t *this, chunk_t args, char *buf)
{
	struct tm loc, utc;
	chunk_t t1, t2;
	time_t t;

	/* Break down local time with format t1 = yyyy-mm-dd and t2 = hh:mm:ss */
	if (!eat_whitespace(&args) || !extract_token(&t1, ' ', &args) ||
		!eat_whitespace(&args) || t1.len != 10 || args.len != 8)
	{
		DBG1(DBG_IMC, "unable to parse start-date");
		return FALSE;
	}
	t2 = args;

	if (sscanf(t1.ptr, "%4d-%2d-%2d",
						&loc.tm_year, &loc.tm_mon, &loc.tm_mday) != 3)
	{
		DBG1(DBG_IMC, "unable to parse date format yyyy-mm-dd");
		return FALSE;
	}
	loc.tm_year -= 1900;
	loc.tm_mon  -= 1;
	loc.tm_isdst = -1;

	if (sscanf(t2.ptr, "%2d:%2d:%2d",
						&loc.tm_hour, &loc.tm_min, &loc.tm_sec) != 3)
	{
		DBG1(DBG_IMC, "unable to parse time format hh:mm:ss");
		return FALSE;
	}

	/* Convert from local time to UTC */
	t = mktime(&loc);
	gmtime_r(&t, &utc);
	utc.tm_year += 1900;
	utc.tm_mon  += 1;

	/* Form timestamp according to RFC 3339 (20 characters) */
	snprintf(buf, 21, "%4d-%02d-%02dT%02d:%02d:%02dZ",
			 utc.tm_year, utc.tm_mon, utc.tm_mday,
			 utc.tm_hour, utc.tm_min, utc.tm_sec);

	return TRUE;
}

METHOD(sw_collector_history_t, extract_packages, bool,
	private_sw_collector_history_t *this, chunk_t args, uint32_t eid,
	sw_collector_history_op_t op)
{
	package_t *p = NULL;
	uint32_t sw_id;
	chunk_t item;
	bool success = FALSE;

	eat_whitespace(&args);

	while (extract_token(&item, ')', &args))
	{
		p = extract_package(item, this->tag_creator, this->os, op);
		if (!p)
		{
			goto end;
		}

		/* packages without version information cannot be handled */
		if (strlen(p->version) == 0)
		{
			free_package(p);
			continue;
		}

		sw_id = this->db->set_sw_id(this->db, p->sw_id, p->package,	p->version,
									this->source, op != SW_OP_REMOVE, FALSE);
		if (!sw_id)
		{
			goto end;
		}
		if (!this->db->add_sw_event(this->db, eid, sw_id, op != SW_OP_REMOVE ?
					SWIMA_EVENT_ACTION_CREATION : SWIMA_EVENT_ACTION_DELETION))
		{
			goto end;
		}

		if (op == SW_OP_UPGRADE)
		{
			sw_id = this->db->set_sw_id(this->db, p->old_sw_id, p->package,
										p->old_version, this->source, FALSE,
										FALSE);
			if (!sw_id)
			{
				goto end;
			}
			if (!this->db->add_sw_event(this->db, eid, sw_id,
										SWIMA_EVENT_ACTION_DELETION))
			{
				goto end;
			}
		}
		free_package(p);

		if (args.len < 2)
		{
			break;
		}
		args = chunk_skip(args, 2);
	}
	p = NULL;
	success = TRUE;

end:
	free_package(p);

	return success;
}

METHOD(sw_collector_history_t, merge_installed_packages, bool,
	private_sw_collector_history_t *this)
{
	FILE *file;
	uint32_t sw_id, count = 0;
	char line[BUF_LEN], *pos, *package, *version, *state, *name;
	bool success = FALSE;
	char cmd[] = "dpkg-query -W -f=\'${Package}\t${Version}\t${Status}\n\'";

	DBG1(DBG_IMC, "Merging:");

	file = popen(cmd, "r");
	if (!file)
	{
		DBG1(DBG_IMC, "failed to run dpgk-query command");
		return FALSE;
	}

	while (TRUE)
	{
		if (!fgets(line, sizeof(line), file))
		{
			break;
		}

		package = line;
		pos = strchr(line, '\t');
		if (!pos)
		{
			goto end;
		}
		*pos = '\0';

		version = ++pos;
		pos = strchr(pos, '\t');
		if (!pos)
		{
			goto end;
		}
		*pos = '\0';

		state = ++pos;
		pos = strchr(pos, '\n');
		if (!pos)
		{
			goto end;
		}
		*pos = '\0';

		if (!streq(state, "install ok installed"))
		{
			continue;
		}
		name = create_sw_id(this->tag_creator, this->os, package, version);
		DBG3(DBG_IMC, "  %s merged", name);

		sw_id = this->db->set_sw_id(this->db, name, package, version,
									this->source, TRUE, TRUE);
		free(name);
		if (!sw_id)
		{
			goto end;
		}
		count++;
	}
	success = TRUE;
	DBG1(DBG_IMC, "  merged %u installed packages, %u registed in database",
		 count, this->db->get_sw_id_count(this->db, SW_QUERY_INSTALLED));

end:
	pclose(file);
	return success;
}

METHOD(sw_collector_history_t, destroy, void,
	private_sw_collector_history_t *this)
{
	this->os_info->destroy(this->os_info);
	free(this->os);
	free(this->product);
	free(this);
}

/**
 * Described in header.
 */
sw_collector_history_t *sw_collector_history_create(sw_collector_db_t *db,
													uint8_t source)
{
	private_sw_collector_history_t *this;
	chunk_t os_name, os_version, os_arch;
	os_type_t os_type;

	INIT(this,
		.public = {
			.get_os = _get_os,
			.extract_timestamp = _extract_timestamp,
			.extract_packages = _extract_packages,
			.merge_installed_packages = _merge_installed_packages,
			.destroy = _destroy,
		},
		.db = db,
		.source = source,
		.os_info = imc_os_info_create(),
		.tag_creator = lib->settings->get_str(lib->settings,
				"%s.tag_creator.regid", "strongswan.org", lib->ns),
	);

	os_type = this->os_info->get_type(this->os_info);
	os_name = this->os_info->get_name(this->os_info);
	os_arch = this->os_info->get_version(this->os_info);

	/* check if OS is supported */
	if (os_type != 	OS_TYPE_DEBIAN && os_type != OS_TYPE_UBUNTU)
	{
		DBG1(DBG_IMC, "%.*s OS not supported", os_name.len, os_name.ptr);
		destroy(this);
		return NULL;
	}

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
