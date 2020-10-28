/*
 * Copyright (C) 2020 Andreas Steffen
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
 * @defgroup oqs_public_key oqs_public_key
 * @{ @ingroup oqs_p
 */

#ifndef OQS_PUBLIC_KEY_H_
#define OQS_PUBLIC_KEY_H_

#include <credentials/builder.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>

typedef struct oqs_public_key_t oqs_public_key_t;

/**
 * public_key_t implementation of OQS signature algorithm
 */
struct oqs_public_key_t {

	/**
	 * Implements the public_key_t interface
	 */
	public_key_t key;
};

/**
 * Load an OQS public key.
 *
 * @param type		type of the key
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
oqs_public_key_t *oqs_public_key_load(key_type_t type, va_list args);

/* The following functions are shared with the oqs_private_key class */

/**
 * Is the key type supported by OQS?
 *
 * @param type		type of the key
 * @return			TRUE if key type is supported
 */
bool oqs_supported(key_type_t type);

/**
 * Generate a public key fingerprint
 *
 * @param pubkey	public key
 * @param oid		OID of the key type
 * @param type		type of fingerprint to be generated
 * @param fp		generated fingerprint (must be freed by caller)
 * @result			TRUE if generation was successful
 */
bool oqs_public_key_fingerprint(chunk_t pubkey, int oid,
								cred_encoding_type_t type, chunk_t *fp);

#endif /** OQS_PUBLIC_KEY_H_ @}*/
