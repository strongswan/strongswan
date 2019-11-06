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
 * @defgroup frodo frodo
 * @{ @ingroup frodo_p
 */

#ifndef FRODO_H_
#define FRODO_H_

typedef struct frodo_t frodo_t;

#include <library.h>

/**
 * Quantum-safe key encapsulation implementation using FrodoKEM
 */
struct frodo_t {

	/**
	 * Implements key_exchange_t interface.
	 */
	key_exchange_t ke;
};

/**
 * Creates a new frodo_t object.
 *
 * @param method		key exchange method
 * @return				frodo_t object, NULL if not supported
 */
frodo_t *frodo_create(key_exchange_method_t method);

#endif /** FRODO_H_ @}*/
