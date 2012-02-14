/* misc. universal things
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

bool
all_zero(const unsigned char *m, size_t len)
{
	size_t i;

	for (i = 0; i != len; i++)
		if (m[i] != '\0')
			return FALSE;
	return TRUE;
}

/*  Note that there may be as many as six IDs that are temporary at
 *  one time before unsharing the two ends of a connection. So we need
 *  at least six temporary buffers for DER_ASN1_DN IDs.
 *  We rotate them. Be careful!
 */
#define MAX_BUF         10

char*
temporary_cyclic_buffer(void)
{
	static char buf[MAX_BUF][BUF_LEN];  /* MAX_BUF internal buffers */
	static int counter = 0;                     /* cyclic counter */

	if (++counter == MAX_BUF) counter = 0;      /* next internal buffer */
	return buf[counter];                        /* assign temporary buffer */
}

/* concatenates two sub paths into a string with a maximum size of BUF_LEN
 * use for temporary storage only
 */
char* concatenate_paths(char *a, char *b)
{
	char *c;

	if (*b == '/' || *b == '.')
		return b;

	c = temporary_cyclic_buffer();
	snprintf(c, BUF_LEN, "%s/%s", a, b);
	return c;
}

/* moves a chunk to a memory position, chunk is freed afterwards
 * position pointer is advanced after the insertion point
 */
void
mv_chunk(u_char **pos, chunk_t content)
{
	if (content.len > 0)
	{
		chunkcpy(*pos, content);
		free(content.ptr);
	}
}

/*  checks if the expiration date has been reached and
 *  warns during the warning_interval of the imminent
 *  expiry. strict=TRUE declares a fatal error,
 *  strict=FALSE issues a warning upon expiry.
 */
const char*
check_expiry(time_t expiration_date, int warning_interval, bool strict)
{
	time_t now, time_left;

	if (expiration_date == UNDEFINED_TIME)
	  return "ok (expires never)";

	/* determine the current time */
	time(&now);

	time_left = (expiration_date - now);
	if (time_left < 0)
		return strict? "fatal (expired)" : "warning (expired)";

	if (time_left > 86400*warning_interval)
		return "ok";
	{
		static char buf[35]; /* temporary storage */
		const char* unit = "second";

		if (time_left > 172800)
		{
			time_left /= 86400;
			unit = "day";
		}
		else if (time_left > 7200)
		{
			time_left /= 3600;
			unit = "hour";
		}
		else if (time_left > 120)
		{
			time_left /= 60;
			unit = "minute";
		}
		snprintf(buf, 35, "warning (expires in %" PRIu64 " %s%s)",
				 (u_int64_t)time_left, unit, (time_left == 1) ? "" : "s");
		return buf;
	}
}


/*
 *  Filter eliminating the directory entries '.' and '..'
 */
int
file_select(const struct dirent *entry)
{
	return strcmp(entry->d_name, "." ) &&
		   strcmp(entry->d_name, "..");
}


