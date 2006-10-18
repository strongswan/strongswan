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

#include <printf.h>
#include <stdio.h>

#include "definitions.h"

/*
 * Described in header
 */
static char *enum_name(enum_name_t *e, long val)
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
 * output handler in printf() for enum names
 */
static int print_enum(FILE *stream, const struct printf_info *info,
					   const void *const *args)
{
	enum_name_t *ed = *((void**)(args[0]));
	long val = *((size_t*)(args[1]));
	char *name;
	
	name = enum_name(ed, val);
	if (name == NULL)
	{
		return fprintf(stream, "(unknown enum value: %ld)", val);
	}
	return fprintf(stream, "%s", name);
}

/**
 * arginfo handler in printf() for enum names
 */
static int print_enum_arginfo(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		/* enum_names ptr */
		argtypes[0] = PA_POINTER;
		/* value */
		argtypes[1] = PA_INT;
	}
	return 2;
}

/**
 * register printf() handlers for enum names
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(ENUM_PRINTF_SPEC, print_enum, print_enum_arginfo);
}
