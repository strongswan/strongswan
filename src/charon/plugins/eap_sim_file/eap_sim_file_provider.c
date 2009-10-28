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

#include "eap_sim_file_provider.h"

#include <daemon.h>

typedef struct private_eap_sim_file_provider_t private_eap_sim_file_provider_t;

/**
 * Private data of an eap_sim_file_provider_t object.
 */
struct private_eap_sim_file_provider_t {

	/**
	 * Public eap_sim_file_provider_t interface.
	 */
	eap_sim_file_provider_t public;

	/**
	 * source of triplets
	 */
	eap_sim_file_triplets_t *triplets;
};

/**
 * Implementation of sim_provider_t.get_triplet
 */
static bool get_triplet(private_eap_sim_file_provider_t *this,
						identification_t *id, char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	identification_t *cand;
	char *c_rand, *c_sres, *c_kc;

	enumerator = this->triplets->create_enumerator(this->triplets);
	while (enumerator->enumerate(enumerator, &cand, &c_rand, &c_sres, &c_kc))
	{
		if (id->matches(id, cand))
		{
			memcpy(rand, c_rand, SIM_RAND_LEN);
			memcpy(sres, c_sres, SIM_SRES_LEN);
			memcpy(kc, c_kc, SIM_KC_LEN);
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Implementation of eap_sim_file_provider_t.destroy.
 */
static void destroy(private_eap_sim_file_provider_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_sim_file_provider_t *eap_sim_file_provider_create(
											eap_sim_file_triplets_t *triplets)
{
	private_eap_sim_file_provider_t *this = malloc_thing(private_eap_sim_file_provider_t);

	this->public.provider.get_triplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))get_triplet;
	this->public.provider.get_quintuplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char xres[AKA_RES_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char autn[AKA_AUTN_LEN]))return_false;
	this->public.provider.resync = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))return_false;
	this->public.provider.is_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))return_null;
	this->public.provider.gen_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))return_null;
	this->public.provider.is_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char [HASH_SIZE_SHA1], u_int16_t *counter))return_null;
	this->public.provider.gen_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char mk[HASH_SIZE_SHA1]))return_null;
	this->public.destroy = (void(*)(eap_sim_file_provider_t*))destroy;

	this->triplets = triplets;

	return &this->public;
}

