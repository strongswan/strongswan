/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "mysql_plugin.h"

#include <library.h>
#include <debug.h>
#include "mysql_database.h"

typedef struct private_mysql_plugin_t private_mysql_plugin_t;

/**
 * private data of mysql_plugin
 */
struct private_mysql_plugin_t {

	/**
	 * public functions
	 */
	mysql_plugin_t public;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_mysql_plugin_t *this)
{
	lib->db->remove_database(lib->db,
							 (database_constructor_t)mysql_database_create);
	mysql_database_deinit();
	free(this);
}

/*
 * see header file
 */
plugin_t *mysql_plugin_create()
{
	private_mysql_plugin_t *this;

	if (!mysql_database_init())
	{
		DBG1(DBG_LIB, "MySQL client library initialization failed");
		return NULL;
	}

	this = malloc_thing(private_mysql_plugin_t);
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	lib->db->add_database(lib->db,
						  (database_constructor_t)mysql_database_create);

	return &this->public.plugin;
}

