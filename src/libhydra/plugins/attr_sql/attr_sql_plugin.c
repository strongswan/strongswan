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

#include <hydra.h>
#include <utils/debug.h>

#include "attr_sql_plugin.h"
#include "sql_attribute.h"

typedef struct private_attr_sql_plugin_t private_attr_sql_plugin_t;

/**
 * private data of attr_sql plugin
 */
struct private_attr_sql_plugin_t {

	/**
	 * implements plugin interface
	 */
	attr_sql_plugin_t public;

	/**
	 * database connection instance
	 */
	database_t *db;

	/**
	 * configuration attributes
	 */
	sql_attribute_t *attribute;
};

METHOD(plugin_t, get_name, char*,
	private_attr_sql_plugin_t *this)
{
	return "attr-sql";
}

METHOD(plugin_t, destroy, void,
	private_attr_sql_plugin_t *this)
{
	hydra->attributes->remove_provider(hydra->attributes, &this->attribute->provider);
	this->attribute->destroy(this->attribute);
	this->db->destroy(this->db);
	free(this);
}

/*
 * see header file
 */
plugin_t *attr_sql_plugin_create()
{
	private_attr_sql_plugin_t *this;
	char *uri;

	uri = lib->settings->get_str(lib->settings, "libhydra.plugins.attr-sql.database",
												 NULL);
	if (!uri)
	{
		DBG1(DBG_CFG, "attr-sql plugin: database URI not set");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.db = lib->db->create(lib->db, uri),
	);

	if (!this->db)
	{
		DBG1(DBG_CFG, "attr-sql plugin failed to connect to database");
		free(this);
		return NULL;
	}
	this->attribute = sql_attribute_create(this->db);
	hydra->attributes->add_provider(hydra->attributes, &this->attribute->provider);

	return &this->public.plugin;
}

