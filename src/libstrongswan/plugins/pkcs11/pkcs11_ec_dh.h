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
 * @defgroup pkcs11_ec_dh pkcs11_ec_dh
 * @{ @ingroup pkcs11_p
 */

#ifndef PKCS11_EC_DH_H_
#define PKCS11_EC_DH_H_

typedef struct pkcs11_ec_dh_t pkcs11_ec_dh_t;

#include <library.h>

/**
 * Implementation of the EC Diffie-Hellman algorithm via PKCS#11.
 */
struct pkcs11_ec_dh_t {

	/**
	 * Implements diffie_hellman_t interface.
	 */
	diffie_hellman_t dh;
};

/**
 * Creates a new pkcs11_ec_dh_t object.
 *
 * @param group			EC Diffie Hellman group number to use
 * @return				pkcs11_ec_dh_t object, NULL if not supported
 */
pkcs11_ec_dh_t *pkcs11_ec_dh_create(diffie_hellman_group_t group);

#endif /** PKCS11_EC_DH_H_ @}*/

