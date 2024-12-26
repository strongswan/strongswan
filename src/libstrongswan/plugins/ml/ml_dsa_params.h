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

/**
 * @defgroup ml_dsa_params ml_dsa_params
 * @{ @ingroup ml_p
 */

#ifndef ML_PARAMS_H_
#define ML_PARAMS_H_

#include <credentials/keys/public_key.h>

typedef struct ml_dsa_params_t ml_dsa_params_t;

/**
 * Constant N used throughout the algorithms.
 */
#define ML_DSA_N  256

/**
 * The prime q = 2^23 - 2^13 + 1.
 */
#define ML_DSA_Q  8380417

/**
 * Number of bits representing (q - 1).
 */
#define ML_DSA_Q_BITS  23

/**
 * The inverse of q mod 2^32.
 */
#define ML_DSA_QINV  58728449

/**
 * Dropped bits from vector t -> (t0, t1)
 */
#define ML_DSA_D  13

/**
 * Number of bits representing element of vector t1.
 */
#define ML_DSA_T1_BITS  ML_DSA_Q_BITS - ML_DSA_D

/**
 * Length of the secret seed, rho, and K
 */
#define ML_DSA_SEED_LEN  32

/**
 * Length of K.
 */
#define ML_DSA_K_LEN  32

/**
 * Length of the public key digest tr.
 */
#define ML_DSA_TR_LEN  64

/**
 * Length of the message representative mu.
 */
#define ML_DSA_MU_LEN  64

/**
 * Length of rnd used for a randomized signature.
 */
#define ML_DSA_RND_LEN  32

/**
 * Length of the random private seed rho_pp.
 */
#define ML_DSA_RHO_PP_LEN  64

/**
 * Parameters for ML-DSA.
 */
struct ml_dsa_params_t {

	/**
	 * Key type.
	 */
	const key_type_t type;

	/**
	 * Number of lines in matrix A.
	 */
	uint8_t k;

	/**
	 * Number of columns in matrix A.
	 */
	uint8_t l;

	/**
	 * Private key range.
	 */
	uint8_t eta;

	/**
	 * Number of bits of a compressesd s1/s2 polynomial coefficient.
	 */
	uint8_t d;

	/**
	 * Power of two exponent of gamma1.
	 */
	u_int gamma1_exp;

	/**
	 * Low-order rounding range.
	 */
	int32_t gamma2;

	/**
	 * Number of bits of a compressed w1 polynomial coefficient.
	 */
	size_t gamma2_d;

	/**
	 * Collision strength of c_tilde.
	 */
	size_t lambda;

	/**
	 * Hamming weight.
	 */
	int32_t tau;

	/**
	 * beta = eta * tau.
	 */
	int32_t beta;

	/**
	 * Maximum number of 1's in the hint h.
	 */
	int32_t omega;

	/**
	 * Private key length in bytes
	 */
	size_t privkey_len;

	/**
	 * Signature length in bytes
	 */
	size_t sig_len;
};

/**
 * Get parameters from a specific ML-DSA algorithm.
 *
 * @param 				type of key
 * @return				parameters, NULL if not supported
 */
const ml_dsa_params_t *ml_dsa_params_get(key_type_t type);

#endif /** ML_PARAMS_H_ @}*/
