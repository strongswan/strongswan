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
 * @defgroup pkcs11_library pkcs11_library
 * @{ @ingroup pkcs11
 */

#ifndef PKCS11_LIBRARY_H_
#define PKCS11_LIBRARY_H_

typedef struct pkcs11_library_t pkcs11_library_t;

#include "pkcs11.h"

/**
 * A loaded and initialized PKCS#11 library.
 */
struct pkcs11_library_t {

	/**
	 * PKCS#11 function list, as returned by C_GetFunctionList
	 */
	CK_FUNCTION_LIST_PTR f;

	/**
	 * Destroy a pkcs11_library_t.
	 */
	void (*destroy)(pkcs11_library_t *this);
};

/**
 * Create a pkcs11_library instance.
 *
 * @param name		an arbitrary name, for debugging
 * @param file		pkcs11 library file to dlopen()
 * @return			library abstraction
 */
pkcs11_library_t *pkcs11_library_create(char *name, char *file);

#endif /** PKCS11_LIBRARY_H_ @}*/
