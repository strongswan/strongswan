/*
 * Copyright (C) 2025 Andreas Steffen
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
 * @defgroup openssl_ml_dsa_private_key openssl_ml_dsa_private_key
 * @{ @ingroup openssl_p
 */

#ifndef OPENSSL_ML_DSA_PRIVATE_KEY_H_
#define OPENSSL_ML_DSA_PRIVATE_KEY_H_

#include <openssl/evp.h>

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

/**
 * Generate an ML-DSA private key using OpenSSL.
 *
 * @param type		type of the key, must be ML_DSA_44, ML_DSA_65 or ML_DSA_87
 * @param args		builder_part_t argument list
 * @return 			generated key, NULL on failure
 */
private_key_t *openssl_ml_dsa_private_key_gen(key_type_t type, va_list args);

/**
 * Load an ML-DSA private key using OpenSSL.
 *
 * Accepts a BUILD_BLOB_ASN1_DER argument.
 *
 * @param type		type of the key, must be ML_DSA_44, ML_DSA_65 or ML_DSA_87
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
private_key_t *openssl_ml_dsa_private_key_load(key_type_t type, va_list args);

#endif /** OPENSSL_ML_DSA_PRIVATE_KEY_H_ @}*/
