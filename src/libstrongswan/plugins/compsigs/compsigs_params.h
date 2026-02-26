/*
 * Copyright (C) 2026 Tobias Brunner
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
 * @defgroup compsigs_params compsigs_params
 * @{ @ingroup compsigs_p
 */

#ifndef COMPSIGS_PARAMS_H_
#define COMPSIGS_PARAMS_H_

#include <credentials/keys/public_key.h>
#include <credentials/keys/signature_params.h>

typedef struct compsigs_params_t compsigs_params_t;

/**
 * Parameters for composite algorithms
 */
struct compsigs_params_t {

	/**
	 * Composite key type.
	 */
	const key_type_t type;

	/**
	 * ML-DSA key type.
	 */
	const key_type_t ml_dsa;

	/**
	 * ML-DSA signature scheme.
	 */
	const signature_scheme_t ml_dsa_sig;

	/**
	 * Length of the ML-DSA siganture.
	 */
	const size_t ml_dsa_sig_len;

	/**
	 * Traditional key type.
	 */
	const key_type_t trad;

	/**
	 * Length of the traditional key.
	 */
	const size_t trad_key_size;

	/**
	 * Curve for ECDSA.
	 */
	const int trad_ecc_curve;

	/**
	 * Traditional signature scheme and parameters.
	 */
	const signature_params_t trad_sig;

	/**
	 * Pre-hash algorithm.
	 */
	const hash_algorithm_t prehash;

	/**
	 * Label used for signatures.
	 */
	const char *label;
};

/**
 * Get the parameters for a specific composite key type.
 *
 * @param type		composite key type
 * @return			parameters, NULL if not supported
 */
const compsigs_params_t *compsigs_params_get(key_type_t type);

#endif /** COMPSIGS_PARAMS_H_ @}*/
