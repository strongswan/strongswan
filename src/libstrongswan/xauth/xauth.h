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
 * @defgroup xauth xauth
 * @{ @ingroup libstrongswan
 */

#ifndef XAUTH_H__
#define XAUTH_H__

typedef enum xauth_type_t xauth_type_t;

#include <library.h>

/**
 * XAuth types, defines the XAuth method implementation
 */
enum xauth_type_t {
	XAUTH_RADIUS = 253,
	XAUTH_NULL = 254,
};

/**
 * enum names for xauth_type_t.
 */
extern enum_name_t *xauth_method_type_names;

/**
 * short string enum names for xauth_type_t.
 */
extern enum_name_t *xauth_method_type_short_names;

/**
 * Lookup the XAuth method type from a string.
 *
 * @param name		XAuth method name (such as "md5", "aka")
 * @return			method type, 0 if unknown
 */
xauth_type_t xauth_type_from_string(char *name);

#endif /** XAUTH_H_ @}*/
