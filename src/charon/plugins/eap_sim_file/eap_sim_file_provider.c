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

#include "eap_sim_file_provider.h"

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
						identification_t *imsi,
						char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	identification_t *id;
	char *c_rand, *c_sres, *c_kc;

	enumerator = this->triplets->create_enumerator(this->triplets);
	while (enumerator->enumerate(enumerator, &id, &c_rand, &c_sres, &c_kc))
	{
		if (imsi->matches(imsi, id))
		{
			memcpy(rand, c_rand, RAND_LEN);
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

	this->public.provider.get_triplet = (bool(*)(sim_provider_t*, identification_t *imsi, char rand[16], char sres[4], char kc[8]))get_triplet;
	this->public.destroy = (void(*)(eap_sim_file_provider_t*))destroy;

	this->triplets = triplets;

	return &this->public;
}

