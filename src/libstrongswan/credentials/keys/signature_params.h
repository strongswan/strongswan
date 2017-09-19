/*
 * Copyright (C) 2017 Tobias Brunner
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

/**
 * @defgroup signature_params signature_params
 * @{ @ingroup keys
 */

#ifndef SIGNATURE_PARAMS_H_
#define SIGNATURE_PARAMS_H_

typedef struct rsa_pss_params_t rsa_pss_params_t;

#include <crypto/hashers/hasher.h>

/**
 * Parameters for SIGN_RSA_EMSA_PSS signature scheme
 */
struct rsa_pss_params_t {
	/** Hash algorithm */
	hash_algorithm_t hash;
	/** Hash for the MGF1 function */
	hash_algorithm_t mgf1_hash;
	/** Salt length, use RSA_PSS_SALT_LEN_DEFAULT for length equal to hash */
	ssize_t salt_len;
#define RSA_PSS_SALT_LEN_DEFAULT -1
};

#endif /** SIGNATURE_PARAMS_H_ @}*/
