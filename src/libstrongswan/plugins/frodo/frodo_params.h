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

/**
 * @defgroup frodo_params frodo_params
 * @{ @ingroup frodo_p
 */

#ifndef FRODO_PARAMS_H_
#define FRODO_PARAMS_H_

#include <library.h>

typedef struct frodo_params_t frodo_params_t;
typedef enum frodo_kem_type_t frodo_kem_type_t;

/**
 * FrodoKEM types with various security strengths
 */
enum frodo_kem_type_t {
	FRODO_KEM_L1,
	FRODO_KEM_L3,
	FRODO_KEM_L5,
};

/**
 * FrodoKEM parameter definitions
 */
struct frodo_params_t {

    /**
	 * Frodo key exchange ID
	 */
	const frodo_kem_type_t id;

	/**
	 * Lattice dimension
	 */
	const uint32_t n;

	/**
	 * Dimension n_bar
	 */
	const uint32_t nb;

	/**
	 * Logarithm of modulus q
	 */
	const uint32_t log_q;

	/**
	 * Extracted bits
	 */
	const uint32_t extr_bits;

	/**
	 * Size of seed_A
	 */
	const uint32_t seed_A_len;

	/**
	 * Size of shared secret
	 */
	const uint32_t ss_len;

	/**
	 * Size of ciphertext
	 */
	const uint32_t ct_len;

	/**
	 * Size of public key
	 */
	const uint32_t pk_len;

	/**
	 * Size of secret key
	 */
	const uint32_t sk_len;

	/**
	 * Size of CDF table
	 */
	const uint32_t cdf_table_len;

	/**
	 * CDF table
	 */
	const uint16_t *cdf_table;

	/**
	 * SHAKE extended output function
	 */
	ext_out_function_t xof_type;
};

/**
 * Get Frodo parameters by Frodo key exchange ID
 *
 * @param id	Frodo KEM ID
 * @return		Frodo parameters
*/
const frodo_params_t* frodo_params_get_by_id(frodo_kem_type_t id);

#endif /** FRODO_PARAMS_H_ @}*/
