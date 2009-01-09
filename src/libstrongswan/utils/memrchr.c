/*
 * Copyright (C) 2008 Thomas Jarosch
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

#ifndef HAVE_MEMRCHR

#include <string.h>

void *memrchr(const void *s, int c, size_t n)
{
	unsigned char *reverse_search;

	if (s == NULL || n == 0)
	{
		return NULL;
	}

	reverse_search = s + n;

	for (;;)
	{
		if (*reverse_search == (unsigned char)c)
		{
			return reverse_search;
		}
		else if (reverse_search == s)
		{
			break;
		}
		reverse_search--;
	}
	return NULL;
}

#endif
