/*
 * Copyright (C) 2006 Martin Willi
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

#include "xauth.h"

ENUM_BEGIN(xauth_method_type_names, XAUTH_RADIUS, XAUTH_NULL,
	"XAUTH_RADIUS",
	"XAUTH_NULL");
ENUM_END(xauth_method_type_names, XAUTH_NULL);

ENUM_BEGIN(xauth_method_type_short_names, XAUTH_RADIUS, XAUTH_NULL,
	"RAD",
	"NULL");
ENUM_END(xauth_method_type_short_names, XAUTH_NULL);

/*
 * See header
 */
xauth_type_t xauth_type_from_string(char *name)
{
	int i;
	static struct {
		char *name;
		xauth_type_t type;
	} types[] = {
		{"radius",		XAUTH_RADIUS},
		{"null",		XAUTH_NULL},
	};

	for (i = 0; i < countof(types); i++)
	{
		if (strcaseeq(name, types[i].name))
		{
			return types[i].type;
		}
	}
	return 0;
}
