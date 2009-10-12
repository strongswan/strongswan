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
};

/**
 * Implementation of sim_card_t.get_triplet
 */
static bool get_triplet(private_eap_sim_file_card_t *this,
						identification_t *imsi, char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	identification_t *id;
	char *c_rand, *c_sres, *c_kc;

	DBG2(DBG_CFG, "looking for rand: %b from %Y", rand, SIM_RAND_LEN, imsi);

	enumerator = this->triplets->create_enumerator(this->triplets);
	while (enumerator->enumerate(enumerator, &id, &c_rand, &c_sres, &c_kc))
	{
		if (imsi->matches(imsi, id))
		{
			DBG2(DBG_CFG, "found triplet: rand %b\nsres %b\n kc %b",
				 c_rand, SIM_RAND_LEN, c_sres, SIM_SRES_LEN, c_kc, SIM_KC_LEN);
			if (memeq(c_rand, rand, SIM_RAND_LEN))
			{
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
	free(this);
}

/**
 * See header
 */
eap_sim_file_card_t *eap_sim_file_card_create(eap_sim_file_triplets_t *triplets)
{
	private_eap_sim_file_card_t *this = malloc_thing(private_eap_sim_file_card_t);

	this->public.card.get_triplet = (bool(*)(sim_card_t*, identification_t *imsi, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))get_triplet;
	this->public.card.get_quintuplet = (status_t(*)(sim_card_t*, identification_t *imsi, char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char res[AKA_RES_LEN]))get_quintuplet;
	this->public.card.resync = (bool(*)(sim_card_t*, identification_t *imsi, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))return_false;
	this->public.destroy = (void(*)(eap_sim_file_card_t*))destroy;

	this->triplets = triplets;

	return &this->public;
}

