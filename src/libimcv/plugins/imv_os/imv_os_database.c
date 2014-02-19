/*
 * Copyright (C) 2012 Andreas Steffen
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

#define _GNU_SOURCE /* for stdndup() */
#include <string.h>

#include "imv_os_database.h"

#include <utils/debug.h>

typedef struct private_imv_os_database_t private_imv_os_database_t;

/**
 * Private data of a imv_os_database_t object.
 *
 */
struct private_imv_os_database_t {

	/**
	 * Public imv_os_database_t interface.
	 */
	imv_os_database_t public;

	/**
	 * database instance
	 */
	database_t *db;

};

METHOD(imv_os_database_t, check_packages, status_t,
	private_imv_os_database_t *this, imv_os_state_t *state,
	enumerator_t *package_enumerator)
{
	char *product, *package, *release, *cur_release;
	chunk_t name, version;
	os_type_t os_type;
	int pid, gid, security, blacklist;
	int count = 0, count_ok = 0, count_no_match = 0, count_blacklist = 0;
	enumerator_t *e;
	status_t status = SUCCESS;
	bool found, match;

	product = state->get_info(state, &os_type, NULL, NULL);

	if (os_type == OS_TYPE_ANDROID)
	{
		/*no package dependency on Android version */
		product = enum_to_name(os_type_names, os_type);
	}
	DBG1(DBG_IMV, "processing installed '%s' packages", product);

	/* Get primary key of product */
	e = this->db->query(this->db,
				"SELECT id FROM products WHERE name = ?",
				DB_TEXT, product, DB_INT);
	if (!e)
	{
		return FAILED;
	}
	if (!e->enumerate(e, &pid))
	{
		e->destroy(e);
		return NOT_FOUND;
	}
	e->destroy(e);

	while (package_enumerator->enumerate(package_enumerator, &name, &version))
	{
		/* Convert package name chunk to a string */
		package = strndup(name.ptr, name.len);
		count++;

		/* Get primary key of package */
		e = this->db->query(this->db,
					"SELECT id FROM packages WHERE name = ?",
					DB_TEXT, package, DB_INT);
		if (!e)
		{
			free(package);
			return FAILED;
		}
		if (!e->enumerate(e, &gid))
		{
			/* package not present in database for any product - skip */
			if (os_type == OS_TYPE_ANDROID)
			{
				DBG2(DBG_IMV, "package '%s' (%.*s) not found",
					 package, version.len, version.ptr);
			}
			free(package);
			e->destroy(e);
			continue;
		}
		e->destroy(e);

		/* Convert package version chunk to a string */
		release = strndup(version.ptr, version.len);

		/* Enumerate over all acceptable versions */
		e = this->db->query(this->db,
				"SELECT release, security, blacklist FROM versions "
				"WHERE product = ? AND package = ?",
				DB_INT, pid, DB_INT, gid, DB_TEXT, DB_INT, DB_INT);
		if (!e)
		{
			free(package);
			free(release);
			return FAILED;
		}
		found = FALSE;
		match = FALSE;

		while (e->enumerate(e, &cur_release, &security, &blacklist))
		{
			found = TRUE;
			if (streq(release, cur_release) || streq("*", cur_release))
			{
				match = TRUE;
				break;
			}
		}
		e->destroy(e);

		if (found)
		{
			if (match)
			{
				if (blacklist)
				{
					DBG2(DBG_IMV, "package '%s' (%s) is blacklisted",
								   package, release);
					count_blacklist++;
					state->add_bad_package(state, package,
										   OS_PACKAGE_STATE_BLACKLIST);
				}
				else
				{
					DBG2(DBG_IMV, "package '%s' (%s)%s is ok", package, release,
								   security ? " [s]" : "");
					count_ok++;
				}
			}
			else
			{
				DBG1(DBG_IMV, "package '%s' (%s) no match", package, release);
				count_no_match++;
				state->add_bad_package(state, package,
									   OS_PACKAGE_STATE_SECURITY);
			}
		}
		else
		{
			/* package not present in database for this product - skip */
		}
		free(package);
		free(release);
	}
	state->set_count(state, count, count_no_match, count_blacklist, count_ok);

	return status;
}

METHOD(imv_os_database_t, set_device_info, void,
	private_imv_os_database_t *this,  int session_id, int count,
	int count_update, int count_blacklist, u_int flags)
{
	this->db->execute(this->db, NULL,
			"INSERT INTO device_infos (session, count, count_update, "
			"count_blacklist, flags) VALUES (?, ?, ?, ?, ?)",
			 DB_INT, session_id, DB_INT, count, DB_INT, count_update,
			 DB_INT, count_blacklist, DB_UINT, flags);
}

METHOD(imv_os_database_t, destroy, void,
	private_imv_os_database_t *this)
{
	free(this);
}

/**
 * See header
 */
imv_os_database_t *imv_os_database_create(imv_database_t *imv_db)
{
	private_imv_os_database_t *this;

	if (!imv_db)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.check_packages = _check_packages,
			.set_device_info = _set_device_info,
			.destroy = _destroy,
		},
		.db = imv_db->get_database(imv_db),
	);

	return &this->public;
}

