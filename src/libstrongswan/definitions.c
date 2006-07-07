/**
 * @file definitions.c
 * 
 * @brief General purpose definitions and macros.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stdlib.h>

#include "definitions.h"

/*
 * Described in header.
 */
char *mapping_find(mapping_t * maps, int value)
{
	int i = 0;
	while (maps[i].value != MAPPING_END)
	{
		if (maps[i].value == value)
		{
			return maps[i].string;
		}
		i++;
	}
	return "INVALID MAPPING";
}

/*
 * Described in header
 */
const char *enum_name(enum_names *ed, unsigned long val)
{
	enum_names	*p;

	for (p = ed; p != NULL; p = p->en_next_range)
	{
		if (p->en_first <= val && val <= p->en_last)
	    	return p->en_names[val - p->en_first];
	}
	return NULL;
}

