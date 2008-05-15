/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup pubkey_public_key pubkey_public_key
 * @{ @ingroup pubkey_p
 */

#ifndef PUBKEY_PUBLIC_KEY_H_
#define PUBKEY_PUBLIC_KEY_H_

#include <credentials/keys/public_key.h>

/**
 * Create the builder for a generic public key.
 *
 * @param type		type of the key, must be KEY_ANY
 * @return 			builder instance
 */
builder_t *pubkey_public_key_builder(key_type_t type);

#endif /*PUBKEY_RSA_PUBLIC_KEY_H_ @}*/
