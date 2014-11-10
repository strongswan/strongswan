/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "bliss_param_set.h"

#include <asn1/oid.h>

ENUM(bliss_param_set_id_names, BLISS_I, BLISS_IV,
	"BLISS-I",
	"BLISS-II",
	"BLISS-III",
	"BLISS-IV"
);

/**
 * BLISS signature parameter set definitions
 */
static bliss_param_set_t bliss_param_sets[] = {

	/* BLISS-I scheme */
    {
        .id = BLISS_I,
		.oid = OID_BLISS_I,
		.strength = 128,
		.q = 12289,
		.n = 512,
		.n_bits = 9,
		.fft_params = &bliss_fft_12289_512,
		.non_zero1 = 154,
		.non_zero2 = 0,
		.kappa = 23,
		.nks_max = 46479,
      },

	/* BLISS-III scheme */
    {
        .id = BLISS_III,
		.oid = OID_BLISS_III,
		.strength = 160,
		.q = 12289,
		.n = 512,
		.n_bits = 9,
		.fft_params = &bliss_fft_12289_512,
		.non_zero1 = 216,
		.non_zero2 = 16,
		.kappa = 30,
		.nks_max = 128626,
      },

	/* BLISS-IV scheme */
    {
        .id = BLISS_IV,
		.oid = OID_BLISS_IV,
		.strength = 192,
		.q = 12289,
		.n = 512,
		.n_bits = 9,
		.fft_params = &bliss_fft_12289_512,
		.non_zero1 = 231,
		.non_zero2 = 31,
		.kappa = 39,
		.nks_max = 244669,
      }
};

/**
 * See header.
 */
bliss_param_set_t* bliss_param_set_get_by_id(bliss_param_set_id_t id)
{
	int i;

	for (i = 0; i < countof(bliss_param_sets); i++)
	{
		if (bliss_param_sets[i].id == id)
		{
			return &bliss_param_sets[i];
		}
	}
	return NULL;
}


/**
 * See header.
 */
bliss_param_set_t* bliss_param_set_get_by_oid(int oid)
{
	int i;

	for (i = 0; i < countof(bliss_param_sets); i++)
	{
		if (bliss_param_sets[i].oid == oid)
		{
			return &bliss_param_sets[i];
		}
	}
	return NULL;
}
