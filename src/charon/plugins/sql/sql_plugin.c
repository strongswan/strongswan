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
#include "sql_cred.h"
#include "sql_logger.h"

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
	
	/**
	 * credential set
	 */
	sql_cred_t *cred;
	
	/**
	 * bus listener/logger
	 */
	sql_logger_t *logger;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_sql_plugin_t *this)
{
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	charon->credentials->remove_set(charon->credentials, &this->cred->set);
	charon->bus->remove_listener(charon->bus, &this->logger->listener);
	this->config->destroy(this->config);
	this->cred->destroy(this->cred);
	this->logger->destroy(this->logger);
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
		DBG1(DBG_CFG, "sql plugin: database URI not set");
		return NULL;
	}
	
	this = malloc_thing(private_sql_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->db = lib->db->create(lib->db, uri);
	if (!this->db)
	{
		DBG1(DBG_CFG, "sql plugin failed to connect to database");
		free(this);
		return NULL;
	}
	this->config = sql_config_create(this->db);
	this->cred = sql_cred_create(this->db);
	this->logger = sql_logger_create(this->db);
	
	charon->backends->add_backend(charon->backends, &this->config->backend);
	charon->credentials->add_set(charon->credentials, &this->cred->set);
	charon->bus->add_listener(charon->bus, &this->logger->listener);
	
	return &this->public.plugin;
}

