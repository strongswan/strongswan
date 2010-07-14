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
 * @defgroup pkcs11_manager pkcs11_manager
 * @{ @ingroup pkcs11
 */

#ifndef PKCS11_MANAGER_H_
#define PKCS11_MANAGER_H_

typedef struct pkcs11_manager_t pkcs11_manager_t;

/**
 * Manages multiple PKCS#11 libraries with hot pluggable slots
 */
struct pkcs11_manager_t {

	/**
	 * Destroy a pkcs11_manager_t.
	 */
	void (*destroy)(pkcs11_manager_t *this);
};

/**
 * Create a pkcs11_manager instance.
 */
pkcs11_manager_t *pkcs11_manager_create();

#endif /** PKCS11_MANAGER_H_ @}*/
