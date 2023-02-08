/*
 * Copyright (C) 2022-2023 Tobias Brunner
 * Copyright (C) 2006 Martin Willi
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

#include <stddef.h>
#include <stdio.h>

#include <library.h>
#include <collections/enumerator.h>
#include <utils/utils.h>

#include "enum.h"

/**
 * See header.
 */
char *enum_to_name(enum_name_t *e, int val)
{
	enum_name_elem_t *cur;

	if (!e)
	{
		return NULL;
	}
	for (cur = e->elem; cur; cur = cur->next)
	{
		if (val >= cur->first && val <= cur->last)
		{
			return cur->names[val - cur->first];
		}
	}
	return NULL;
}

/**
 * See header.
 */
bool enum_from_name_as_int(enum_name_t *e, const char *name, int *val)
{
	enum_name_elem_t *cur;

	if (!e)
	{
		return FALSE;
	}
	for (cur = e->elem; cur; cur = cur->next)
	{
		int i, count = cur->last - cur->first + 1;

		for (i = 0; i < count; i++)
		{
			if (name && strcaseeq(name, cur->names[i]))
			{
				*val = cur->first + i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Get the position of a flag name using offset calculation
 */
static int find_flag_pos(u_int first, u_int val)
{
	int offset = 0;

	while (first != 0x01)
	{
		first = first >> 1;
		offset++;
	}
	/* skip the first name as that's used if no flag is set */
	return 1 + val - offset;
}

/**
 * Described in header.
 */
char *enum_flags_to_string(enum_name_t *e, u_int val, char *buf, size_t len)
{
	enum_name_elem_t *cur;
	char *pos = buf, *delim = "";
	int i, wr;

	if (!e)
	{
		return NULL;
	}
	cur = e->elem;
	if (cur->next != ENUM_FLAG_MAGIC)
	{
		if (snprintf(buf, len, "(%d)", (int)val) >= len)
		{
			return NULL;
		}
		return buf;
	}

	if (snprintf(buf, len, "%s", cur->names[0]) >= len)
	{
		return NULL;
	}

	for (i = 0; val; i++)
	{
		u_int flag = 1 << i;

		if (val & flag)
		{
			char *name = NULL, hex[32];

			if (flag >= (u_int)cur->first && flag <= (u_int)cur->last)
			{
				name = cur->names[find_flag_pos(cur->first, i)];
			}
			else
			{
				snprintf(hex, sizeof(hex), "(0x%X)", flag);
				name = hex;
			}
			if (name)
			{
				wr = snprintf(pos, len, "%s%s", delim, name);
				if (wr >= len)
				{
					return NULL;
				}
				len -= wr;
				pos += wr;
				delim = " | ";
			}
			val &= ~flag;
		}
	}
	return buf;
}

/*
 * Described in header
 */
bool enum_flags_from_string_as_int(enum_name_t *e, const char *str, u_int *val)
{
	enum_name_elem_t *cur;
	enumerator_t *enumerator;
	char *name;

	*val = 0;

	if (!e || !str || !*str)
	{
		return TRUE;
	}
	cur = e->elem;
	if (cur->next != ENUM_FLAG_MAGIC)
	{
		return enum_from_name_as_int(e, str, val);
	}

	enumerator = enumerator_create_token(str, "|", " ");
	while (enumerator->enumerate(enumerator, &name))
	{
		u_int flag, i;
		bool found = FALSE;

		if (strcaseeq(name, cur->names[0]))
		{	/* accept name used if no flags are set */
			continue;
		}
		for (i = 1, flag = cur->first; flag <= cur->last; i++, flag <<= 1)
		{
			if (cur->names[i] && strcaseeq(name, cur->names[i]))
			{
				*val |= flag;
				found = TRUE;
				break;
			}
		}
		if (!found)
		{
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * See header.
 */
int enum_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
					 const void *const *args)
{
	enum_name_t *ed = *((enum_name_t**)(args[0]));
	int val = *((int*)(args[1]));
	char *name, buf[512];

	if (ed && ed->elem->next == ENUM_FLAG_MAGIC)
	{
		name = enum_flags_to_string(ed, val, buf, sizeof(buf));
		if (name == NULL)
		{
			snprintf(buf, sizeof(buf), "(0x%X)", val);
			name = buf;
		}
	}
	else
	{
		name = enum_to_name(ed, val);
		if (name == NULL)
		{
			snprintf(buf, sizeof(buf), "(%d)", val);
			name = buf;
		}
	}
	if (spec->minus)
	{
		return print_in_hook(data, "%-*s", spec->width, name);
	}
	return print_in_hook(data, "%*s", spec->width, name);
}
