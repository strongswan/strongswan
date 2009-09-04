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

#include "eap_sim_file_card.h"

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
	 * IMSI, is ID_ANY for file implementation
	 */
	identification_t *imsi;

	/**
 	 * source of triplets
 	 */
	eap_sim_file_triplets_t *triplets;
};

#include <daemon.h>

/**
 * Implementation of sim_card_t.get_triplet
 */
static bool get_triplet(private_eap_sim_file_card_t *this,
						char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	identification_t *id;
	char *c_rand, *c_sres, *c_kc;

	DBG2(DBG_CFG, "looking for rand: %b", rand, RAND_LEN);

	enumerator = this->triplets->create_enumerator(this->triplets);
	while (enumerator->enumerate(enumerator, &id, &c_rand, &c_sres, &c_kc))
	{
		DBG2(DBG_CFG, "found triplet: rand %b\nsres %b\n kc %b",
			 c_rand, RAND_LEN, c_sres, SRES_LEN, c_kc, KC_LEN);
		if (memeq(c_rand, rand, RAND_LEN))
		{
			memcpy(sres, c_sres, SRES_LEN);
			memcpy(kc, c_kc, KC_LEN);
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Implementation of sim_card_t.get_imsi
 */
static identification_t* get_imsi(private_eap_sim_file_card_t *this)
{
	return this->imsi;
}

/**
 * Implementation of eap_sim_file_card_t.destroy.
 */
static void destroy(private_eap_sim_file_card_t *this)
{
	this->imsi->destroy(this->imsi);
	free(this);
}

/**
 * See header
 */
eap_sim_file_card_t *eap_sim_file_card_create(eap_sim_file_triplets_t *triplets)
{
	private_eap_sim_file_card_t *this = malloc_thing(private_eap_sim_file_card_t);

	this->public.card.get_triplet = (bool(*)(sim_card_t*, char *rand, char *sres, char *kc))get_triplet;
	this->public.card.get_imsi = (identification_t*(*)(sim_card_t*))get_imsi;
	this->public.destroy = (void(*)(eap_sim_file_card_t*))destroy;

	/* this SIM card implementation does not have an ID, serve ID_ANY */
	this->imsi = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->triplets = triplets;

	return &this->public;
}

