/*
 * Copyright (C) 2009 Martin Willi
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

#include "eap_simaka_reauth_plugin.h"
#include "eap_simaka_reauth_card.h"
#include "eap_simaka_reauth_provider.h"

#include <daemon.h>

typedef struct private_eap_simaka_reauth_t private_eap_simaka_reauth_t;

/**
 * Private data of an eap_simaka_reauth_t object.
 */
struct private_eap_simaka_reauth_t {

	/**
	 * Public eap_simaka_reauth_plugin_t interface.
	 */
	eap_simaka_reauth_plugin_t public;

	/**
	 * SIM card
	 */
	eap_simaka_reauth_card_t *card;

	/**
	 * SIM provider
	 */
	eap_simaka_reauth_provider_t *provider;
};

/**
 * Implementation of eap_simaka_reauth_t.destroy.
 */
static void destroy(private_eap_simaka_reauth_t *this)
{
	charon->sim->remove_card(charon->sim, &this->card->card);
	charon->sim->remove_provider(charon->sim, &this->provider->provider);
	this->card->destroy(this->card);
	this->provider->destroy(this->provider);
	free(this);
}

/**
 * See header
 */
plugin_t *eap_simaka_reauth_plugin_create()
{
	private_eap_simaka_reauth_t *this = malloc_thing(private_eap_simaka_reauth_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	this->provider = eap_simaka_reauth_provider_create();
	if (!this->provider)
	{
		free(this);
		return NULL;
	}
	this->card = eap_simaka_reauth_card_create();

	charon->sim->add_card(charon->sim, &this->card->card);
	charon->sim->add_provider(charon->sim, &this->provider->provider);

	return &this->public.plugin;
}

