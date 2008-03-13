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

#include "med_db_plugin.h"

#include "med_db_creds.h"

#include <daemon.h>

typedef struct private_med_db_plugin_t private_med_db_plugin_t;

/**
 * private data of med_db plugin
 */
struct private_med_db_plugin_t {

	/**
	 * implements plugin interface
	 */
	med_db_plugin_t public;
	
	/**
	 * database connection instance
	 */
	database_t *db;
	
	/**
	 * med_db credential set instance
	 */
	med_db_creds_t *creds;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_med_db_plugin_t *this)
{
	charon->credentials->remove_set(charon->credentials, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	char *uri;
	private_med_db_plugin_t *this = malloc_thing(private_med_db_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	uri = lib->settings->get_str(lib->settings, "plugins.med_db.database", NULL);
	if (!uri)
	{
		DBG1(DBG_CFG, "mediation database URI not defined, skipped");
		free(this);
		return NULL;
	}
	
	if (this->db == NULL)
	{
		DBG1(DBG_CFG, "opening mediation server database failed");
		free(this);
		return NULL;
	}
	
	this->creds = med_db_creds_create(this->db);
	
	charon->credentials->add_set(charon->credentials, &this->creds->set);
	
	return &this->public.plugin;
}

