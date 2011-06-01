/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "imcv.h"

#include "utils.h"
#include <debug.h>

#include <syslog.h>

/**
 * Reference count for IMC/IMV instances
 */
refcount_t ref = 0;

/**
 * Global configuration of libimcv dbg function
 */
static int debug_level = 3;
static bool stderr_quiet = FALSE;

/**
 * libimvc dbg function
 */
static void libimcv_dbg(debug_t group, level_t level, char *fmt, ...)
{
	int priority = LOG_INFO;
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (level <= debug_level)
	{
		if (!stderr_quiet)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
			va_end(args);
		}

		/* write in memory buffer first */
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);

		/* do a syslog with every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			syslog(priority, "%s\n", current);
			current = next;
		}
	}
}

/**
 * Described in header.
 */
bool libimcv_init(void)
{
	/* initialize libstrongswan library only once */
	if (lib)
	{
		/* did main program initialize libstrongswan? */
		if (ref == 0)
		{
			ref_get(&ref);
		}
	}
	else
	{
		/* we are the first to initialize libstrongswan */
		if (!library_init(NULL))
		{
			return FALSE;
		}

		if (!lib->plugins->load(lib->plugins, NULL, "random"))
		{
			library_deinit();
			return FALSE;
		}

		/* enable libimcv debugging hook */
		dbg = libimcv_dbg;
		openlog("imcv", 0, LOG_DAEMON);

		DBG1(DBG_LIB, "libimcv initialized");
	}
	ref_get(&ref);

	return TRUE;
}

/**
 * Described in header.
 */
void libimcv_deinit(void)
{
	if (ref_put(&ref))
	{
		DBG1(DBG_LIB, "libimcv terminated");
		library_deinit();		
	}
}


