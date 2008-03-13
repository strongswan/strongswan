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
 *
 * $Id$
 */

#include "sql_plugin.h"

#include <daemon.h>
#include "sql_config.h"

typedef struct private_sql_plugin_t private_sql_plugin_t;

/**
 * private data of sql plugin
 */
struct private_sql_plugin_t {

	/**
	 * implements plugin interface
	 */
	sql_plugin_t public;
	
	/**
	 * database connection instance
	 */
	database_t *db;
	
	/**
	 * configuration backend
	 */
	sql_config_t *config;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_sql_plugin_t *this)
{
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	this->config->destroy(this->config);
	this->db->destroy(this->db);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	char *uri;
	private_sql_plugin_t *this;
	
	uri = lib->settings->get_str(lib->settings, "charon.plugins.sql.database", NULL);
	if (!uri)
	{
		DBG1(DBG_CFG, "SQL plugin database URI not set");
		return NULL;
	}
	
	this = malloc_thing(private_sql_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->db = lib->db->create(lib->db, uri);
	if (!this->db)
	{
		DBG1(DBG_CFG, "SQL plugin failed to connect to database");
		free(this);
		return NULL;
	}
	this->config = sql_config_create(this->db);
		
	charon->backends->add_backend(charon->backends, &this->config->backend);
	
	return &this->public.plugin;
}

