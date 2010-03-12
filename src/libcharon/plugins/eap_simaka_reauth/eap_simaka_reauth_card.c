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

#include "eap_simaka_reauth_card.h"

#include <daemon.h>
#include <utils/hashtable.h>

typedef struct private_eap_simaka_reauth_card_t private_eap_simaka_reauth_card_t;

/**
 * Private data of an eap_simaka_reauth_card_t object.
 */
struct private_eap_simaka_reauth_card_t {

	/**
	 * Public eap_simaka_reauth_card_t interface.
	 */
	eap_simaka_reauth_card_t public;

	/**
	 * Permanent -> reauth_data_t mappings
	 */
	hashtable_t *reauth;
};

/**
 * Data associated to a reauthentication identity
 */
typedef struct {
	/** currently used reauthentication identity */
	identification_t *id;
	/** associated permanent identity */
	identification_t *permanent;
	/** counter value */
	u_int16_t counter;
	/** master key */
	char mk[HASH_SIZE_SHA1];
} reauth_data_t;

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
 * Implementation of sim_card_t.get_reauth
 */
static identification_t *get_reauth(private_eap_simaka_reauth_card_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter)
{
	reauth_data_t *data;
	identification_t *reauth;

	/* look up reauthentication data */
	data = this->reauth->remove(this->reauth, id);
	if (!data)
	{
		return NULL;
	}
	*counter = ++data->counter;
	memcpy(mk, data->mk, HASH_SIZE_SHA1);
	reauth = data->id;
	data->permanent->destroy(data->permanent);
	free(data);
	return reauth;
}

/**
 * Implementation of sim_card_t.set_reauth
 */
static void set_reauth(private_eap_simaka_reauth_card_t *this,
					   identification_t *id, identification_t* next,
					   char mk[HASH_SIZE_SHA1], u_int16_t counter)
{
	reauth_data_t *data;

	data = this->reauth->get(this->reauth, id);
	if (data)
	{
		data->id->destroy(data->id);
	}
	else
	{
		data = malloc_thing(reauth_data_t);
		data->permanent = id->clone(id);
		this->reauth->put(this->reauth, data->permanent, data);
	}
	data->counter = counter;
	data->id = next->clone(next);
	memcpy(data->mk, mk, HASH_SIZE_SHA1);
}

/**
 * Implementation of sim_card_t.get_quintuplet
 */
static status_t get_quintuplet()
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of eap_simaka_reauth_card_t.destroy.
 */
static void destroy(private_eap_simaka_reauth_card_t *this)
{
	enumerator_t *enumerator;
	reauth_data_t *data;
	void *key;

	enumerator = this->reauth->create_enumerator(this->reauth);
	while (enumerator->enumerate(enumerator, &key, &data))
	{
		data->id->destroy(data->id);
		data->permanent->destroy(data->permanent);
		free(data);
	}
	enumerator->destroy(enumerator);

	this->reauth->destroy(this->reauth);
	free(this);
}

/**
 * See header
 */
eap_simaka_reauth_card_t *eap_simaka_reauth_card_create()
{
	private_eap_simaka_reauth_card_t *this;

	this = malloc_thing(private_eap_simaka_reauth_card_t);

	this->public.card.get_triplet = (bool(*)(sim_card_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))return_null;
	this->public.card.get_quintuplet = (status_t(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len))get_quintuplet;
	this->public.card.resync = (bool(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))return_false;
	this->public.card.get_pseudonym = (identification_t*(*)(sim_card_t*, identification_t *perm))return_null;
	this->public.card.set_pseudonym = (void(*)(sim_card_t*, identification_t *id, identification_t *pseudonym))nop;
	this->public.card.get_reauth = (identification_t*(*)(sim_card_t*, identification_t *id, char mk[HASH_SIZE_SHA1], u_int16_t *counter))get_reauth;
	this->public.card.set_reauth = (void(*)(sim_card_t*, identification_t *id, identification_t* next, char mk[HASH_SIZE_SHA1], u_int16_t counter))set_reauth;
	this->public.destroy = (void(*)(eap_simaka_reauth_card_t*))destroy;

	this->reauth = hashtable_create((void*)hash, (void*)equals, 0);

	return &this->public;
}

