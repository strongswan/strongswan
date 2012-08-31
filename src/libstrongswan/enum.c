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

#include <stddef.h>
#include <stdio.h>

#include <library.h>

#include "enum.h"

/**
 * See header.
 */
char *enum_to_name(enum_name_t *e, int val)
{
	enum_name_elem_t *current;

	current = e->elem;
	while (current)
	{
		if (val >= current->first && val <= current->last)
		{
			return current->names[val - current->first];
		}
		current = current->next;
	}
	return NULL;
}

/**
 * See header.
 */
int enum_from_name(enum_name_t *e, char *name)
{
	enum_name_elem_t *current;

	current = e->elem;
	while (current)
	{
		int i, count = current->last - current->first + 1;

		for (i = 0; i < count; i++)
		{
			if (strcaseeq(name, current->names[i]))
			{
				return current->first + i;
			}
		}
		current = current->next;
	}
	return -1;
}

/**
 * Described in header.
 */
int enum_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
					 const void *const *args)
{
	enum_name_t *e;
	int val;
	char *name;

	e = *((enum_name_t**)(args[0]));
	val = *((int*)(args[1]));
	name = enum_to_name(e, val);
	if (name == NULL)
	{
		return print_in_hook(data, "(%d)", val);
	}
	else
	{
		return print_in_hook(data, "%s", name);
	}
}

/**
 * Described in header.
 */
int enum_dynamic_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
							 const void *const *args)
{
	enum_name_t *e;
	enum_name_get_t e_get;
	int val, id = 0;
	char *name = NULL;

	e_get = *((enum_name_get_t*)(args[0]));
	id = *((int*)(args[1]));
	val = *((int*)(args[2]));

	e = e_get(id);
	if (e)
	{
		name = enum_to_name(e, val);
	}
	if (name == NULL)
	{
		return print_in_hook(data, "(%d)", val);
	}
	else
	{
		return print_in_hook(data, "%s", name);
	}
}
