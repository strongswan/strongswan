/*
 * Copyright (C) 2019 Andreas Steffen
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
 * Quantum-safe key encapsulation implementation using ephemeral FrodoKEM.
 *
 * @defgroup frodo_kem frodo_kem
 * @{ @ingroup frodo_p
 */

#ifndef FRODO_KEM_H_
#define FRODO_KEM_H_

#include <library.h>

/**
 * Creates a new key_exchange_t object.
 *
 * @param method		key exchange method
 * @return				key_exchange_t object, NULL if not supported
 */
key_exchange_t *frodo_kem_create(key_exchange_method_t method);

#endif /** FRODO_KEM_H_ @}*/
