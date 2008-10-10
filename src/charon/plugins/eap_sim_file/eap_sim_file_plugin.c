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

#include "eap_sim_file_plugin.h"
#include "eap_sim_file_card.h"
#include "eap_sim_file_provider.h"
#include "eap_sim_file_triplets.h"

#include <daemon.h>

#define TRIPLET_FILE IPSEC_CONFDIR "/ipsec.d/triplets.dat"

typedef struct private_eap_sim_file_t private_eap_sim_file_t;

/**
 * Private data of an eap_sim_file_t object.
 */
struct private_eap_sim_file_t {
	
	/**
	 * Public eap_sim_file_plugin_t interface.
	 */
	eap_sim_file_plugin_t public;
	
	/**
	 * SIM card
	 */
	eap_sim_file_card_t *card;
	
	/**
	 * SIM provider
	 */
	eap_sim_file_provider_t *provider;
	
	/**
	 * Triplet source
	 */
	eap_sim_file_triplets_t *triplets;
};

/**
 * Implementation of eap_sim_file_t.destroy.
 */
static void destroy(private_eap_sim_file_t *this)
{
	charon->sim->remove_card(charon->sim, &this->card->card);
	charon->sim->remove_provider(charon->sim, &this->provider->provider);
	this->card->destroy(this->card);
	this->provider->destroy(this->provider);
	this->triplets->destroy(this->triplets);
	free(this);
}

/**
 * See header
 */
plugin_t *plugin_create()
{
	private_eap_sim_file_t *this = malloc_thing(private_eap_sim_file_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->triplets = eap_sim_file_triplets_create(TRIPLET_FILE);
	this->card = eap_sim_file_card_create(this->triplets);
	this->provider = eap_sim_file_provider_create(this->triplets);
	
	charon->sim->add_card(charon->sim, &this->card->card);
	charon->sim->add_provider(charon->sim, &this->provider->provider);
	
	return &this->public.plugin;
}

