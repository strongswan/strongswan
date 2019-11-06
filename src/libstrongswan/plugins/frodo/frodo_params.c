/*
 * MIT License
 *
 * Copyright (C) Microsoft Corporation
 *
 * Copyright (C) 2019 Andreas Steffen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "frodo_params.h"

const uint16_t cdf_table_1[] = { 4643, 13363, 20579, 25843, 29227,
								  31145, 32103, 32525, 32689, 32745,
								  32762, 32766, 32767
							   };
const uint16_t cdf_table_3[] = {  5638, 15915, 23689, 28571, 31116,
								 32217, 32613, 32731, 32760, 32766,
								 32767
							   };
const uint16_t cdf_table_5[] = {  9142, 23462, 30338, 32361, 32725,
								 32765, 32767
							   };

/**
 * FrodoKEM parameter definitions
 */
static const frodo_params_t frodo_params[] = {

	{
		FRODO_KEM_L1,              /* Frodo KEM ID                    */
		640,                       /* Lattice dimension n             */
		8,                         /* Dimension n_bar                 */
		15,                        /* Logarithm of modulus q          */
		2,                         /* Extracted bits extr_bits        */
		16,                        /* Size of seed_A seed_A_len       */
		16,                        /* Size of shared secret ss_len    */
		9720,                      /* Size of ciphertext ct_len       */
		9616,                      /* Size of public key pk_len       */
		19888,                     /* Size of secret key sk_len       */
		13,                        /* Size of CDF table cdf_table_len */
		cdf_table_1,               /* CDF table                       */
		XOF_SHAKE_128,             /* SHAKE XOF                       */
    },

	{
		FRODO_KEM_L3,              /* Frodo KEM ID                    */
		976,                       /* Lattice dimension n             */
		8,                         /* Dimension n_bar                 */
		16,                        /* Logarithm of modulus q          */
		3,                         /* Extracted bits extr_bits        */
		16,                        /* Size of seed_A seed_A_len       */
		24,                        /* Size of shared secret ss_len    */
		15744,                     /* Size of ciphertext ct_len       */
		15632,                     /* Size of public key pk_len       */
		31296,                     /* Size of secret key sk_len       */
		11,                        /* Size of CDF table cdf_table_len */
		cdf_table_3,               /* CDF table                       */
		XOF_SHAKE_256,             /* SHAKE XOF                       */
    },

	{
		FRODO_KEM_L5,              /* Frodo KEM ID                    */
		1344,                      /* Lattice dimension n             */
		8,                         /* Dimension n_bar                 */
		16,                        /* Logarithm of modulus q          */
		4,                         /* Extracted bits extr_bits        */
		16,                        /* Size of seed_A seed_A_len       */
		32,                        /* Size of shared secret ss_len    */
		21632,                     /* Size of ciphertext ct_len       */
		21520,                     /* Size of public key pk_len       */
		43088,                     /* Size of secret key sk_len       */
		7,                         /* Size of CDF table cdf_table_len */
		cdf_table_5,               /* CDF table                       */
		XOF_SHAKE_256,             /* SHAKE XOF                       */
    },
};

/**
 * See header.
 */
const frodo_params_t* frodo_params_get_by_id(frodo_kem_type_t id)
{
	int i;

	for (i = 0; i < countof(frodo_params); i++)
	{
		if (frodo_params[i].id == id)
		{
			return &frodo_params[i];
		}
	}
	return NULL;
}
