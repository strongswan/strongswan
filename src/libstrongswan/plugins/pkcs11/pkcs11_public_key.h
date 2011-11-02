/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup pkcs11_public_key pkcs11_public_key
 * @{ @ingroup pkcs11
 */

#ifndef PKCS11_PUBLIC_KEY_H_
#define PKCS11_PUBLIC_KEY_H_

typedef struct pkcs11_public_key_t pkcs11_public_key_t;

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

/**
 * PKCS#11 based public key implementation.
 */
struct pkcs11_public_key_t {

	/**
	 * Implements public_key_t.
	 */
	public_key_t key;
};

/**
 * Create a public key in a PKCS#11 session.
 *
 * @param type		type of the key
 * @param args		builder_part_t argument list
 * @return			loaded key, NULL on failure
 */
pkcs11_public_key_t *pkcs11_public_key_load(key_type_t type, va_list args);

#endif /** PKCS11_PUBLIC_KEY_H_ @}*/
