/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup pkcs1_public_key pkcs1_public_key
 * @{ @ingroup pkcs1_p
 */

#ifndef PKCS1_BUILDER_H_
#define PKCS1_BUILDER_H_

#include <credentials/keys/public_key.h>

/**
 * Create the builder for a generic or an RSA public key.
 *
 * @param type		type of the key, either KEY_ANY or KEY_RSA
 * @return 			builder instance
 */
builder_t *pkcs1_public_key_builder(key_type_t type);

/**
 * Create the builder for a RSA private key.
 *
 * @param type		type of the key, KEY_RSA
 * @return 			builder instance
 */
builder_t *pkcs1_private_key_builder(key_type_t type);

#endif /** PKCS1_BUILDER_H_ @}*/
