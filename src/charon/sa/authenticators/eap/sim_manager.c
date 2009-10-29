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

#include "sim_manager.h"

#include <daemon.h>
#include <utils/linked_list.h>

typedef struct private_sim_manager_t private_sim_manager_t;

/**
 * Private data of an sim_manager_t object.
 */
struct private_sim_manager_t {

	/**
	 * Public sim_manager_t interface.
	 */
	sim_manager_t public;

	/**
	 * list of added cards
	 */
	linked_list_t *cards;

	/**
	 * list of added provider
	 */
	linked_list_t *providers;
};

/**
 * Implementation of sim_manager_t.add_card
 */
static void add_card(private_sim_manager_t *this, sim_card_t *card)
{
	this->cards->insert_last(this->cards, card);
}

/**
 * Implementation of sim_manager_t.remove_card
 */
static void remove_card(private_sim_manager_t *this, sim_card_t *card)
{
	this->cards->remove(this->cards, card, NULL);
}

/**
 * Implementation of sim_manager_t.card_get_triplet
 */
static bool card_get_triplet(private_sim_manager_t *this, identification_t *id,
							 char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN],
							 char kc[SIM_KC_LEN])
{
	enumerator_t *enumerator;
	sim_card_t *card;
	int tried = 0;

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		if (card->get_triplet(card, id, rand, sres, kc))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
		tried++;
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM cards, but none has triplets for '%Y'",
		 tried, id);
	return FALSE;
}

/**
 * Implementation of sim_manager_t.card_get_quintuplet
 */
static status_t card_get_quintuplet(private_sim_manager_t *this,
								identification_t *id, char rand[AKA_RAND_LEN],
								char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
								char ik[AKA_IK_LEN], char res[AKA_RES_LEN])
{
	enumerator_t *enumerator;
	sim_card_t *card;
	status_t status = NOT_FOUND;
	int tried = 0;

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		status = card->get_quintuplet(card, id, rand, autn, ck, ik, res);
		if (status != FAILED)
		{	/* try next on error, but not on INVALID_STATE */
			enumerator->destroy(enumerator);
			return status;
		}
		tried++;
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM cards, but none has quintuplets for '%Y'",
		 tried, id);
	return status;
}

/**
 * Implementation of sim_manager_t.card_resync
 */
static bool card_resync(private_sim_manager_t *this, identification_t *id,
						char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	enumerator_t *enumerator;
	sim_card_t *card;

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		if (card->resync(card, id, rand, auts))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Implementation of sim_manager_t.card_set_pseudonym
 */
static void card_set_pseudonym(private_sim_manager_t *this,
							identification_t *id, identification_t *pseudonym)
{
	enumerator_t *enumerator;
	sim_card_t *card;

	DBG1(DBG_IKE, "storing pseudonym '%Y' for '%Y'", pseudonym, id);

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		card->set_pseudonym(card, id, pseudonym);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of sim_manager_t.card_get_pseudonym
 */
static identification_t* card_get_pseudonym(private_sim_manager_t *this,
											identification_t *id)
{
	enumerator_t *enumerator;
	sim_card_t *card;
	identification_t *pseudonym = NULL;

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		pseudonym = card->get_pseudonym(card, id);
		if (pseudonym)
		{
			DBG1(DBG_IKE, "using stored pseudonym identity '%Y' "
				 "instead of '%Y'", pseudonym, id);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return pseudonym;
}

/**
 * Implementation of sim_manager_t.card_set_reauth
 */
static void card_set_reauth(private_sim_manager_t *this, identification_t *id,
							identification_t *next, char mk[HASH_SIZE_SHA1],
							u_int16_t counter)
{
	enumerator_t *enumerator;
	sim_card_t *card;

	DBG1(DBG_IKE, "storing next reauthentication identity '%Y' for '%Y'",
		 next, id);

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		card->set_reauth(card, id, next, mk, counter);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of sim_manager_t.card_get_reauth
 */
static identification_t* card_get_reauth(private_sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter)
{
	enumerator_t *enumerator;
	sim_card_t *card;
	identification_t *reauth = NULL;

	enumerator = this->cards->create_enumerator(this->cards);
	while (enumerator->enumerate(enumerator, &card))
	{
		reauth = card->get_reauth(card, id, mk, counter);
		if (reauth)
		{
			DBG1(DBG_IKE, "using stored reauthentication identity '%Y' "
				 "instead of '%Y'", reauth, id);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return reauth;
}

/**
 * Implementation of sim_manager_t.add_provider
 */
static void add_provider(private_sim_manager_t *this, sim_provider_t *provider)
{
	this->providers->insert_last(this->providers, provider);
}

/**
 * Implementation of sim_manager_t.remove_provider
 */
static void remove_provider(private_sim_manager_t *this,
							sim_provider_t *provider)
{
	this->providers->remove(this->providers, provider, NULL);
}

/**
 * Implementation of sim_manager_t.provider_get_triplet
 */
static bool provider_get_triplet(private_sim_manager_t *this,
								 identification_t *id, char rand[SIM_RAND_LEN],
								 char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN])
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	int tried = 0;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_triplet(provider, id, rand, sres, kc))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
		tried++;
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM providers, but none had a triplet for '%Y'",
		 tried, id);
	return FALSE;
}

/**
 * Implementation of sim_manager_t.provider_get_quintuplet
 */
static bool provider_get_quintuplet(private_sim_manager_t *this,
								identification_t *id, char rand[AKA_RAND_LEN],
								char xres[AKA_RES_LEN], char ck[AKA_CK_LEN],
								char ik[AKA_IK_LEN], char autn[AKA_AUTN_LEN])
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	int tried = 0;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_quintuplet(provider, id, rand, xres, ck, ik, autn))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM providers, but none had a quintuplet for '%Y'",
		 tried, id);
	return FALSE;
}

/**
 * Implementation of sim_manager_t.provider_resync
 */
static bool provider_resync(private_sim_manager_t *this, identification_t *id,
							char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	enumerator_t *enumerator;
	sim_provider_t *provider;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->resync(provider, id, rand, auts))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Implementation of sim_manager_t.provider_is_pseudonym
 */
static identification_t* provider_is_pseudonym(private_sim_manager_t *this,
											   identification_t *id)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *permanent = NULL;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		permanent = provider->is_pseudonym(provider, id);
		if (permanent)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return permanent;
}

/**
 * Implementation of sim_manager_t.provider_gen_pseudonym
 */
static identification_t* provider_gen_pseudonym(private_sim_manager_t *this,
												identification_t *id)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *pseudonym = NULL;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		pseudonym = provider->gen_pseudonym(provider, id);
		if (pseudonym)
		{
			DBG1(DBG_IKE, "proposing new pseudonym '%Y'", pseudonym);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return pseudonym;
}

/**
 * Implementation of sim_manager_t.provider_is_reauth
 */
static identification_t* provider_is_reauth(private_sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *permanent = NULL;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		permanent = provider->is_reauth(provider, id, mk, counter);
		if (permanent)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return permanent;
}

/**
 * Implementation of sim_manager_t.provider_gen_reauth
 */
static identification_t* provider_gen_reauth(private_sim_manager_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1])
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *reauth = NULL;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		reauth = provider->gen_reauth(provider, id, mk);
		if (reauth)
		{
			DBG1(DBG_IKE, "proposing new reauthentication identity '%Y'", reauth);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return reauth;
}

/**
 * Implementation of sim_manager_t.destroy.
 */
static void destroy(private_sim_manager_t *this)
{
	this->cards->destroy(this->cards);
	this->providers->destroy(this->providers);
	free(this);
}

/**
 * See header
 */
sim_manager_t *sim_manager_create()
{
	private_sim_manager_t *this = malloc_thing(private_sim_manager_t);

	this->public.add_card = (void(*)(sim_manager_t*, sim_card_t *card))add_card;
	this->public.remove_card = (void(*)(sim_manager_t*, sim_card_t *card))remove_card;
	this->public.card_get_triplet = (bool(*)(sim_manager_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))card_get_triplet;
	this->public.card_get_quintuplet = (status_t(*)(sim_manager_t*, identification_t *id, char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char res[AKA_RES_LEN]))card_get_quintuplet;
	this->public.card_resync = (bool(*)(sim_manager_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))card_resync;
	this->public.card_set_pseudonym = (void(*)(sim_manager_t*, identification_t *id, identification_t *pseudonym))card_set_pseudonym;
	this->public.card_get_pseudonym = (identification_t*(*)(sim_manager_t*, identification_t *id))card_get_pseudonym;
	this->public.card_set_reauth = (void(*)(sim_manager_t*, identification_t *id, identification_t *next, char mk[HASH_SIZE_SHA1], u_int16_t counter))card_set_reauth;
	this->public.card_get_reauth = (identification_t*(*)(sim_manager_t*, identification_t *id, char mk[HASH_SIZE_SHA1], u_int16_t *counter))card_get_reauth;
	this->public.add_provider = (void(*)(sim_manager_t*, sim_provider_t *provider))add_provider;
	this->public.remove_provider = (void(*)(sim_manager_t*, sim_provider_t *provider))remove_provider;
	this->public.provider_get_triplet = (bool(*)(sim_manager_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))provider_get_triplet;
	this->public.provider_get_quintuplet = (bool(*)(sim_manager_t*, identification_t *id, char rand[AKA_RAND_LEN], char xres[AKA_RES_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char autn[AKA_AUTN_LEN]))provider_get_quintuplet;
	this->public.provider_resync = (bool(*)(sim_manager_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))provider_resync;
	this->public.provider_is_pseudonym = (identification_t*(*)(sim_manager_t*, identification_t *id))provider_is_pseudonym;
	this->public.provider_gen_pseudonym = (identification_t*(*)(sim_manager_t*, identification_t *id))provider_gen_pseudonym;
	this->public.provider_is_reauth = (identification_t*(*)(sim_manager_t*, identification_t *id, char mk[HASH_SIZE_SHA1], u_int16_t *counter))provider_is_reauth;
	this->public.provider_gen_reauth = (identification_t*(*)(sim_manager_t*, identification_t *id, char mk[HASH_SIZE_SHA1]))provider_gen_reauth;
	this->public.destroy = (void(*)(sim_manager_t*))destroy;

	this->cards = linked_list_create();
	this->providers = linked_list_create();

	return &this->public;
}

