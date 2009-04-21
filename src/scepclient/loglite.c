/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
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
 *
 * RCSID $Id: loglite.c,v 1.2 2005/07/11 18:38:16 as Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <freeswan.h>
#include <debug.h>

#include <constants.h>
#include <defs.h>
#include <log.h>
#include <whack.h>

bool
	log_to_stderr = FALSE,      /* should log go to stderr? */
	log_to_syslog = TRUE;       /* should log go to syslog? */

/**
 * @brief scepclient dbg function
 */
static void scepclient_dbg(int level, char *fmt, ...)
{
	int priority = LOG_INFO;
	int debug_level;
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (cur_debugging & DBG_PRIVATE)
	{
		debug_level = 4;
	}
	else if (cur_debugging & DBG_RAW)
	{
		debug_level = 3;
	}	
	else if (cur_debugging & DBG_PARSING)
	{
		debug_level = 2;
	}
	else 
	{
		debug_level = 1;
	}

	if (level <= debug_level)
	{
		va_start(args, fmt);

		if (log_to_stderr)
		{
			if (level > 1)
			{
				fprintf(stderr, "| ");
			}
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
		}
		if (log_to_syslog)
		{
			/* write in memory buffer first */
			vsnprintf(buffer, sizeof(buffer), fmt, args);

			/* do a syslog with every line */
			while (current)
			{
				next = strchr(current, '\n');
				if (next)
				{
					*(next++) = '\0';
				}
				syslog(priority, "%s%s\n", (level > 1)? "| ":"", current);
				current = next;
			}
		}
		va_end(args);
	}
}

void init_log(const char *program)
{
	/* enable scepclient bugging hook */
	dbg = scepclient_dbg;

	if (log_to_stderr)
	{
		setbuf(stderr, NULL);
	}
	if (log_to_syslog)
	{
		openlog(program, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_AUTHPRIV);
	}
}

void close_log(void)
{
	if (log_to_syslog)
		closelog();
}

void plog(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "%s\n", m);
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);
}

void loglog(int mess_no, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "%s\n", m);
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);
}

void log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "ERROR: %s. Errno %d: %s", m, e, strerror(e));
}

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "FATAL ERROR: %s\n", m);
	if (log_to_syslog)
		syslog(LOG_ERR, "FATAL ERROR: %s", m);
	exit(1);
}

void exit_log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "FATAL ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));
	exit(1);
}

void whack_log(int mess_no, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "%s\n", m);
}

/* Build up a diagnostic in a static buffer.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
char diag_space[sizeof(diag_space)];

err_t builddiag(const char *fmt, ...)
{
	static char diag_space[LOG_WIDTH];  /* longer messages will be truncated */
	char t[sizeof(diag_space)]; /* build result here first */
	va_list args;

	va_start(args, fmt);
	t[0] = '\0';        /* in case nothing terminates string */
	vsnprintf(t, sizeof(t), fmt, args);
	va_end(args);
	strcpy(diag_space, t);
	return diag_space;
}

/* Debugging message support */

#ifdef DEBUG

void switch_fail(int n, const char *file_str, unsigned long line_no)
{
	char buf[30];

	snprintf(buf, sizeof(buf), "case %d unexpected", n);
	passert_fail(buf, file_str, line_no);
}

void passert_fail(const char *pred_str, const char *file_str, unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
	abort();    /* exiting correctly doesn't always work */
}

lset_t
	base_debugging = DBG_NONE,  /* default to reporting nothing */
	cur_debugging =  DBG_NONE;

void pexpect_log(const char *pred_str, const char *file_str, unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	loglog(RC_LOG_SERIOUS, "EXPECTATION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
}

/* log a debugging message (prefixed by "| ") */

void DBG_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];  /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "| %s\n", m);
	if (log_to_syslog)
		syslog(LOG_DEBUG, "| %s", m);
}

/* dump raw bytes in hex to stderr (for lack of any better destination) */

void DBG_dump(const char *label, const void *p, size_t len)
{
#   define DUMP_LABEL_WIDTH 20  /* arbitrary modest boundary */
#   define DUMP_WIDTH   (4 * (1 + 4 * 3) + 1)
	char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
	char *bp;
	const unsigned char *cp = p;

	bp = buf;

	if (label != NULL && label[0] != '\0')
	{
		/* Handle the label.  Care must be taken to avoid buffer overrun. */
		size_t llen = strlen(label);

		if (llen + 1 > sizeof(buf))
		{
			DBG_log("%s", label);
		}
		else
		{
			strcpy(buf, label);
			if (buf[llen-1] == '\n')
			{
				buf[llen-1] = '\0';     /* get rid of newline */
				DBG_log("%s", buf);
			}
			else if (llen < DUMP_LABEL_WIDTH)
			{
				bp = buf + llen;
			}
			else
			{
				DBG_log("%s", buf);
			}
		}
	}

	do {
		int i, j;

		for (i = 0; len!=0 && i!=4; i++)
		{
			*bp++ = ' ';
			for (j = 0; len!=0 && j!=4; len--, j++)
			{
				static const char hexdig[] = "0123456789abcdef";

				*bp++ = ' ';
				*bp++ = hexdig[(*cp >> 4) & 0xF];
				*bp++ = hexdig[*cp & 0xF];
				cp++;
			}
		}
		*bp = '\0';
		DBG_log("%s", buf);
		bp = buf;
	} while (len != 0);
#   undef DUMP_LABEL_WIDTH
#   undef DUMP_WIDTH
}

#endif /* DEBUG */
