/* strongSwan IPsec exec helper function
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"

#include "exec.h"

#define BUF_SIZE  2048

/**
 * TODO:
 * o log stdout with LOG_LEVEL_INFO and stderr with LOG_LEVEL_ERR
 */

int
starter_exec(const char *fmt, ...)
{
	va_list args;
	static char buf[BUF_SIZE];
	int r;

	va_start (args, fmt);
	vsnprintf(buf, BUF_SIZE-1, fmt, args);
	buf[BUF_SIZE - 1] = '\0';
	va_end(args);
	r = system(buf);
	DBG(DBG_CONTROL,
		DBG_log("starter_exec(%s) = %d", buf, r)
	)
	return r;
}

