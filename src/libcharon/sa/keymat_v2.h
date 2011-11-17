/*
 * Copyright (C) 2011 Tobias Brunner
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
 * @defgroup keymat_v2 keymat_v2
 * @{ @ingroup sa
 */

#ifndef KEYMAT_V2_H_
#define KEYMAT_V2_H_

#include <sa/keymat.h>

typedef struct keymat_v2_t keymat_v2_t;

/**
 * Derivation and management of sensitive keying material, IKEv2 variant.
 */
struct keymat_v2_t {

	/**
	 * Implements keymat_t.
	 */
	keymat_t keymat;
};

/**
 * Create a keymat instance.
 *
 * @param initiator			TRUE if we are the initiator
 * @return					keymat instance
 */
keymat_v2_t *keymat_v2_create(bool initiator);

#endif /** KEYMAT_V2_H_ @}*/
