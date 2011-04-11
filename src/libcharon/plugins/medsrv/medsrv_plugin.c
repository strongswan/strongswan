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

#include "medsrv_plugin.h"

#include "medsrv_creds.h"
#include "medsrv_config.h"

#include <daemon.h>

typedef struct private_medsrv_plugin_t private_medsrv_plugin_t;

/**
 * private data of medsrv plugin
 */
struct private_medsrv_plugin_t {

	/**
	 * implements plugin interface
	 */
	medsrv_plugin_t public;

	/**
	 * database connection instance
	 */
	database_t *db;

	/**
	 * medsrv credential set instance
	 */
	medsrv_creds_t *creds;

	/**
	 * medsrv config database
	 */
	medsrv_config_t *config;
};

METHOD(plugin_t, get_name, char*,
	private_medsrv_plugin_t *this)
{
	return "medsrv";
}

METHOD(plugin_t, destroy, void,
	private_medsrv_plugin_t *this)
{
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->config->destroy(this->config);
	this->creds->destroy(this->creds);
	this->db->destroy(this->db);
	free(this);
}

/*
 * see header file
 */
plugin_t *medsrv_plugin_create()
{
	char *uri;
	private_medsrv_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	uri = lib->settings->get_str(lib->settings,
								 "medsrv.database", NULL);
	if (!uri)
	{
		DBG1(DBG_CFG, "mediation database URI not defined, skipped");
		free(this);
		return NULL;
	}

	this->db = lib->db->create(lib->db, uri);
	if (this->db == NULL)
	{
		DBG1(DBG_CFG, "opening mediation server database failed");
		free(this);
		return NULL;
	}

	this->creds = medsrv_creds_create(this->db);
	this->config = medsrv_config_create(this->db);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);
	charon->backends->add_backend(charon->backends, &this->config->backend);

	return &this->public.plugin;
}

