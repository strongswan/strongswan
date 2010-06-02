/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "eap_simaka_sql_plugin.h"
#include "eap_simaka_sql_card.h"
#include "eap_simaka_sql_provider.h"

#include <daemon.h>

typedef struct private_eap_simaka_sql_t private_eap_simaka_sql_t;

/**
 * Private data of an eap_simaka_sql_t object.
 */
struct private_eap_simaka_sql_t {

	/**
	 * Public eap_simaka_sql_plugin_t interface.
	 */
	eap_simaka_sql_plugin_t public;

	/**
	 * (U)SIM card
	 */
	eap_simaka_sql_card_t *card;

	/**
	 * (U)SIM provider
	 */
	eap_simaka_sql_provider_t *provider;

	/**
	 * Database with triplets/quintuplets
	 */
	database_t *db;
};

METHOD(plugin_t, destroy, void,
	private_eap_simaka_sql_t *this)
{
	charon->sim->remove_card(charon->sim, &this->card->card);
	charon->sim->remove_provider(charon->sim, &this->provider->provider);
	this->card->destroy(this->card);
	this->provider->destroy(this->provider);
	this->db->destroy(this->db);
	free(this);
}

/**
 * See header
 */
plugin_t *eap_simaka_sql_plugin_create()
{
	private_eap_simaka_sql_t *this;
	database_t *db;
	bool remove_used;
	char *uri;

	uri = lib->settings->get_str(lib->settings,
							"charon.plugins.eap-simaka-sql.database", NULL);
	if (!uri)
	{
		DBG1(DBG_CFG, "eap-simaka-sql database URI missing");
		return NULL;
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		DBG1(DBG_CFG, "opening eap-simaka-sql database failed");
		return NULL;
	}
	remove_used = lib->settings->get_bool(lib->settings,
							"charon.plugins.eap-simaka-sql.remove_used", FALSE);

	INIT(this,
		.public.plugin =  {
			.destroy = _destroy,
		},
		.db = db,
		.provider = eap_simaka_sql_provider_create(db, remove_used),
		.card = eap_simaka_sql_card_create(db, remove_used),
	);

	charon->sim->add_card(charon->sim, &this->card->card);
	charon->sim->add_provider(charon->sim, &this->provider->provider);

	return &this->public.plugin;
}
