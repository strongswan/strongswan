/*
 * Copyright (C) 2011 Duncan Salerno
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

#include "eap_sim_pcsc_plugin.h"
#include "eap_sim_pcsc_card.h"

#include <daemon.h>

typedef struct private_eap_sim_pcsc_plugin_t private_eap_sim_pcsc_plugin_t;

/**
 * Private data of an eap_sim_pcsc_t object.
 */
struct private_eap_sim_pcsc_plugin_t {

	/**
	 * Public eap_sim_pcsc_plugin_t interface.
	 */
	eap_sim_pcsc_plugin_t public;

	/**
	 * SIM card
	 */
	eap_sim_pcsc_card_t *card;
};

METHOD(plugin_t, get_name, char*,
	private_eap_sim_pcsc_plugin_t *this)
{
	return "eap-sim-pcsc";
}

METHOD(plugin_t, destroy, void,
	private_eap_sim_pcsc_plugin_t *this)
{
	simaka_manager_t *mgr;

	mgr = lib->get(lib, "sim-manager");
	if (mgr)
	{
		mgr->remove_card(mgr, &this->card->card);
	}
	this->card->destroy(this->card);
	free(this);
}

/**
 * See header
 */
plugin_t *eap_sim_pcsc_plugin_create()
{
	private_eap_sim_pcsc_plugin_t *this;
	simaka_manager_t *mgr;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.card = eap_sim_pcsc_card_create(),
	);

	mgr = lib->get(lib, "sim-manager");
	if (mgr)
	{
		mgr->add_card(mgr, &this->card->card);
	}
	return &this->public.plugin;
}

