/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "eap_aka_3gpp2_plugin.h"
#include "eap_aka_3gpp2_card.h"
#include "eap_aka_3gpp2_provider.h"
#include "eap_aka_3gpp2_functions.h"

#include <daemon.h>

typedef struct private_eap_aka_3gpp2_t private_eap_aka_3gpp2_t;

/**
 * Private data of an eap_aka_3gpp2_t object.
 */
struct private_eap_aka_3gpp2_t {

	/**
	 * Public eap_aka_3gpp2_plugin_t interface.
	 */
	eap_aka_3gpp2_plugin_t public;

	/**
	 * USIM card
	 */
	eap_aka_3gpp2_card_t *card;

	/**
	 * USIM provider
	 */
	eap_aka_3gpp2_provider_t *provider;

	/**
	 * AKA functions
	 */
	eap_aka_3gpp2_functions_t *functions;
};

/**
 * Implementation of eap_aka_3gpp2_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_t *this)
{
	charon->usim->remove_card(charon->usim, &this->card->card);
	charon->usim->remove_provider(charon->usim, &this->provider->provider);
	this->card->destroy(this->card);
	this->provider->destroy(this->provider);
	this->functions->destroy(this->functions);
	free(this);
}

/**
 * See header
 */
plugin_t *plugin_create()
{
	private_eap_aka_3gpp2_t *this = malloc_thing(private_eap_aka_3gpp2_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	this->functions = eap_aka_3gpp2_functions_create();
	this->card = eap_aka_3gpp2_card_create(this->functions);
	this->provider = eap_aka_3gpp2_provider_create(this->functions);

	charon->usim->add_card(charon->usim, &this->card->card);
	charon->usim->add_provider(charon->usim, &this->provider->provider);

	return &this->public.plugin;
}

