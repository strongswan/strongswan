/*
 * Copyright (C) 2018-2019 Andreas Steffen
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
 * @defgroup oqs_kem oqs_kem
 * @{ @ingroup oqs_p
 */

#ifndef OQS_KEM_H_
#define OQS_KEM_H_

typedef struct oqs_kem_t oqs_kem_t;

#include <crypto/key_exchange.h>

/**
 * Quantum-safe key encapsulation implementation using the OQS_KEM library
 */
struct oqs_kem_t {

	/**
	 * Implements the key_exchange_t interface
	 */
	key_exchange_t ke;
};

/**
 * Creates a new oqs_kem_t object.
 *
 * @param method		QSKE mechanism number
 * @return				oqs_kem_t object, NULL if not supported
 */
oqs_kem_t *oqs_kem_create(key_exchange_method_t method);

#endif /** OQS_KEM_H_ @}*/

