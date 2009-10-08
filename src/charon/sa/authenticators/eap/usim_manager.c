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

#include "usim_manager.h"

#include <utils/linked_list.h>

typedef struct private_usim_manager_t private_usim_manager_t;

/**
 * Private data of an usim_manager_t object.
 */
struct private_usim_manager_t {

	/**
	 * Public usim_manager_t interface.
	 */
	usim_manager_t public;

	/**
	 * list of added cards
	 */
	linked_list_t *cards;

	/**
	 * list of added provider
	 */
	linked_list_t *provider;
};

/**
 * Implementation of usim_manager_t.add_card
 */
static void add_card(private_usim_manager_t *this, usim_card_t *card)
{
	this->cards->insert_last(this->cards, card);
}

/**
 * Implementation of usim_manager_t.remove_card
 */
static void remove_card(private_usim_manager_t *this, usim_card_t *card)
{
	this->cards->remove(this->cards, card, NULL);
}

/**
 * Implementation of usim_manager_t.create_card_enumerator
 */
static enumerator_t* create_card_enumerator(private_usim_manager_t *this)
{
	return this->cards->create_enumerator(this->cards);
}

/**
 * Implementation of usim_manager_t.add_provider
 */
static void add_provider(private_usim_manager_t *this,
							  usim_provider_t *provider)
{
	this->provider->insert_last(this->provider, provider);
}

/**
 * Implementation of usim_manager_t.remove_provider
 */
static void remove_provider(private_usim_manager_t *this,
								usim_provider_t *provider)
{
	this->provider->remove(this->provider, provider, NULL);
}

/**
 * Implementation of usim_manager_t.create_provider_enumerator
 */
static enumerator_t* create_provider_enumerator(private_usim_manager_t *this)
{
	return this->provider->create_enumerator(this->provider);
}

/**
 * Implementation of usim_manager_t.destroy.
 */
static void destroy(private_usim_manager_t *this)
{
	this->cards->destroy(this->cards);
	this->provider->destroy(this->provider);
	free(this);
}

/**
 * See header
 */
usim_manager_t *usim_manager_create()
{
	private_usim_manager_t *this = malloc_thing(private_usim_manager_t);

	this->public.add_card = (void(*)(usim_manager_t*, usim_card_t *card))add_card;
	this->public.remove_card = (void(*)(usim_manager_t*, usim_card_t *card))remove_card;
	this->public.create_card_enumerator = (enumerator_t*(*)(usim_manager_t*))create_card_enumerator;
	this->public.add_provider = (void(*)(usim_manager_t*, usim_provider_t *provider))add_provider;
	this->public.remove_provider = (void(*)(usim_manager_t*, usim_provider_t *provider))remove_provider;
	this->public.create_provider_enumerator = (enumerator_t*(*)(usim_manager_t*))create_provider_enumerator;
	this->public.destroy = (void(*)(usim_manager_t*))destroy;

	this->cards = linked_list_create();
	this->provider = linked_list_create();

	return &this->public;
}

