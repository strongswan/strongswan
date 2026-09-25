/*
 * Copyright (C) 2024 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include "ml_dsa_params.h"

/**
 * Parameter sets for ML-DSA.
 */
static const ml_dsa_params_t ml_dsa_params[] = {
	{
		.type = KEY_ML_DSA_44,
		.k = 4,
		.l = 4,
		.eta = 2,
		.d = 3,
		.gamma1_exp = 17,
		.gamma2 = (ML_DSA_Q - 1) / 88,
		.gamma2_d = 6,
		.lambda = 128,
		.tau = 39,
		.beta = 78,
		.omega = 80,
		.privkey_len = 2560,
		.sig_len = 2420,
	},
	{
		.type = KEY_ML_DSA_65,
		.k = 6,
		.l = 5,
		.eta = 4,
		.d = 4,
		.gamma1_exp = 19,
		.gamma2_d = 4,
		.gamma2 = (ML_DSA_Q - 1) / 32,
		.lambda = 192,
		.tau = 49,
		.beta = 196,
		.omega = 55,
		.privkey_len = 4032,
		.sig_len = 3309,
	},
	{
		.type = KEY_ML_DSA_87,
		.k = 8,
		.l = 7,
		.eta = 2,
		.d = 3,
		.gamma1_exp = 19,
		.gamma2 = (ML_DSA_Q - 1) / 32,
		.gamma2_d = 4,
		.lambda = 256,
		.tau = 60,
		.beta = 120,
		.omega = 75,
		.privkey_len = 4896,
		.sig_len = 4627,

	},
};

/*
 * Described in header
 */
const ml_dsa_params_t *ml_dsa_params_get(key_type_t type)
{
	int i;

	for (i = 0; i < countof(ml_dsa_params); i++)
	{
		if (ml_dsa_params[i].type == type)
		{
			return &ml_dsa_params[i];
		}
	}
	return NULL;
}
