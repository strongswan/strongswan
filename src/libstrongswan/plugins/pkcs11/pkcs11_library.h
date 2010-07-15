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

#include <enum.h>
#include <utils/enumerator.h>

/**
 * A loaded and initialized PKCS#11 library.
 */
struct pkcs11_library_t {

	/**
	 * PKCS#11 function list, as returned by C_GetFunctionList
	 */
	CK_FUNCTION_LIST_PTR f;

	/**
	 * Get the name this instance was created with.
	 *
	 * @return			name, as passed to constructor
	 */
	char* (*get_name)(pkcs11_library_t *this);

	/**
	 * Create an enumerator over CK_OBJECT_HANDLE using a search template.
	 *
	 * @param session	session to use
	 * @param tmpl		search template
	 * @param count 	number of attributes in the search template
	 */
	enumerator_t* (*create_object_enumerator)(pkcs11_library_t *this,
			CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count);

	/**
	 * Destroy a pkcs11_library_t.
	 */
	void (*destroy)(pkcs11_library_t *this);
};

/**
 * Enum names for CK_RV return values
 */
extern enum_name_t *ck_rv_names;

/**
 * Enum names for CK_MECHANISM_TYPE values
 */
extern enum_name_t *ck_mech_names;

/**
 * Trim/null terminate a string returned by the varius PKCS#11 functions.
 *
 * @param str		string to trim
 * @param len		max length of the string
 */
void pkcs11_library_trim(char *str, int len);

/**
 * Create a pkcs11_library instance.
 *
 * @param name		an arbitrary name, for debugging
 * @param file		pkcs11 library file to dlopen()
 * @return			library abstraction
 */
pkcs11_library_t *pkcs11_library_create(char *name, char *file);

#endif /** PKCS11_LIBRARY_H_ @}*/
