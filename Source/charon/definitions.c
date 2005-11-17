/**
 * @file definitions.c
 * 
 * @brief general purpose functions used in definitions.h
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "definitions.h"

/*
 * see header
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
