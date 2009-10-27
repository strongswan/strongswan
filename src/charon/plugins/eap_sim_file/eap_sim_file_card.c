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

#include "eap_sim_file_card.h"

#include <daemon.h>
#include <utils/hashtable.h>

typedef struct private_eap_sim_file_card_t private_eap_sim_file_card_t;

/**
 * Private data of an eap_sim_file_card_t object.
 */
struct private_eap_sim_file_card_t {

	/**
	 * Public eap_sim_file_card_t interface.
	 */
	eap_sim_file_card_t public;

	/**
	 * source of triplets
	 */
	eap_sim_file_triplets_t *triplets;

	/**
	 * Permanent -> pseudonym mappongs
	 */
	hashtable_t *pseudonym;

	/**
	 * Pseudonym -> permanent mappings
	 */
	hashtable_t *permanent;
};

/**
 * hashtable hash function
 */
static u_int hash(identification_t *key)
{
	return chunk_hash(key->get_encoding(key));
}

/**
 * hashtable equals function
 */
static bool equals(identification_t *key1, identification_t *key2)
{
	return key1->equals(key1, key2);
}

/**
 * Implementation of sim_card_t.get_triplet
 */
static bool get_triplet(private_eap_sim_file_card_t *this,
						identification_t *id, char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	identification_t *cand;
	char *c_rand, *c_sres, *c_kc;

	DBG2(DBG_CFG, "looking for triplet: %Y rand %b", id, rand, SIM_RAND_LEN);

	enumerator = this->triplets->create_enumerator(this->triplets);
	while (enumerator->enumerate(enumerator, &cand, &c_rand, &c_sres, &c_kc))
	{
		DBG2(DBG_CFG, "got a triplet: %Y rand %b\nsres %b\n kc %b", cand,
			 c_rand, SIM_RAND_LEN, c_sres, SIM_SRES_LEN, c_kc, SIM_KC_LEN);
		if (id->matches(id, cand))
		{
			if (memeq(c_rand, rand, SIM_RAND_LEN))
			{
				DBG2(DBG_CFG, "  => triplet matches");
				memcpy(sres, c_sres, SIM_SRES_LEN);
				memcpy(kc, c_kc, SIM_KC_LEN);
				enumerator->destroy(enumerator);
				return TRUE;
			}
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Implementation of sim_card_t.get_pseudonym
 */
static identification_t *get_pseudonym(private_eap_sim_file_card_t *this,
									   identification_t *id)
{
	identification_t *pseudonym;

	pseudonym = this->pseudonym->get(this->pseudonym, id);
	if (pseudonym)
	{
		return pseudonym->clone(pseudonym);
	}
	return NULL;
}

/**
 * Implementation of sim_card_t.set_pseudonym
 */
static void set_pseudonym(private_eap_sim_file_card_t *this,
						  identification_t *id, identification_t *pseudonym)
{
	identification_t *permanent;

	/* create new entries */
	id = id->clone(id);
	pseudonym = pseudonym->clone(pseudonym);
	permanent = this->permanent->put(this->permanent, pseudonym, id);
	pseudonym = this->pseudonym->put(this->pseudonym, id, pseudonym);

	/* delete old entries */
	DESTROY_IF(permanent);
	DESTROY_IF(pseudonym);
}

/**
 * Implementation of sim_card_t.get_quintuplet
 */
static bool get_quintuplet()
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of eap_sim_file_card_t.destroy.
 */
static void destroy(private_eap_sim_file_card_t *this)
{
	enumerator_t *enumerator;
	identification_t *key, *value;

	enumerator = this->pseudonym->create_enumerator(this->pseudonym);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		value->destroy(value);
	}
	enumerator->destroy(enumerator);

	enumerator = this->permanent->create_enumerator(this->permanent);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		value->destroy(value);
	}
	enumerator->destroy(enumerator);

	this->pseudonym->destroy(this->pseudonym);
	this->permanent->destroy(this->permanent);
	free(this);
}

/**
 * See header
 */
eap_sim_file_card_t *eap_sim_file_card_create(eap_sim_file_triplets_t *triplets)
{
	private_eap_sim_file_card_t *this = malloc_thing(private_eap_sim_file_card_t);

	this->public.card.get_triplet = (bool(*)(sim_card_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))get_triplet;
	this->public.card.get_quintuplet = (status_t(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char res[AKA_RES_LEN]))get_quintuplet;
	this->public.card.resync = (bool(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))return_false;
	this->public.card.get_pseudonym = (identification_t*(*)(sim_card_t*, identification_t *perm))get_pseudonym;
	this->public.card.set_pseudonym = (void(*)(sim_card_t*, identification_t *id, identification_t *pseudonym))set_pseudonym;
	this->public.card.get_reauth = (identification_t*(*)(sim_card_t*, identification_t *id, char mk[HASH_SIZE_SHA1], u_int16_t *counter))return_null;
	this->public.card.set_reauth = (void(*)(sim_card_t*, identification_t *id, identification_t* next, char mk[HASH_SIZE_SHA1], u_int16_t counter))nop;
	this->public.destroy = (void(*)(eap_sim_file_card_t*))destroy;

	this->triplets = triplets;
	this->pseudonym = hashtable_create((void*)hash, (void*)equals, 0);
	this->permanent = hashtable_create((void*)hash, (void*)equals, 0);

	return &this->public;
}

