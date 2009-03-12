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
 *
 * $Id$
 */

#include <stddef.h>
#include <stdio.h>

#include "enum.h"

/**
 * get the name of an enum value in a enum_name_t list
 */
static char *enum_name(enum_name_t *e, int val)
{
	do
	{
		if (val >= e->first && val <= e->last)
		{
			return e->names[val - e->first];
		}
	}
	while ((e = e->next));
	return NULL;
}

/**
 * Described in header.
 */
int enum_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					 const void *const *args)
{
	enum_name_t *ed = *((enum_name_t**)(args[0]));
	int val = *((int*)(args[1]));

	char *name = enum_name(ed, val);

	if (name == NULL)
	{
		return print_in_hook(dst, len, "(%d)", val);
	}
	else
	{
		return print_in_hook(dst, len, "%s", name);
	}
}
