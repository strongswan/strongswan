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

#include <stdarg.h>
#include <stdio.h>

#include "debug.h"

/**
 * level logged by the default logger
 */
static int default_level = 1;

/**
 * stream logged to by the default logger
 */
static FILE *default_stream = NULL;

/**
 * default dbg function which printf all to stderr
 */
void dbg_default(int level, char *fmt, ...)
{
	if (!default_stream)
	{
		default_stream = stderr;
	}
	if (level <= default_level)
	{
		va_list args;

		va_start(args, fmt);
		vfprintf(default_stream, fmt, args);
		fprintf(default_stream, "\n");
		va_end(args);
	}
}

/**
 * set the level logged by the default stderr logger
 */
void dbg_default_set_level(int level)
{
	default_level = level;
}

/**
 * set the stream logged by dbg_default() to
 */
void dbg_default_set_stream(FILE *stream)
{
	default_stream = stream;
}

/**
 * The registered debug hook.
 */
void (*dbg) (int level, char *fmt, ...) = dbg_default;

