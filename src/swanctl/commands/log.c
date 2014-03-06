/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "command.h"

#include <errno.h>
#include <unistd.h>

CALLBACK(log_cb, void,
	bool *raw, char *name, vici_res_t *msg)
{
	if (*raw)
	{
		vici_dump(msg, "log", stdout);
	}
	else
	{
		char *current, *next;

		current = vici_find_str(msg, NULL, "msg");
		while (current)
		{
			next = strchr(current, '\n');
			printf("%.2d[%s] ", vici_find_int(msg, 0, "thread"),
				   vici_find_str(msg, "   ", "group"));
			if (next == NULL)
			{
				printf("%s\n", current);
				break;
			}
			printf("%.*s\n", (int)(next - current), current);
			current = next + 1;
		}
	}
}

static int logcmd(vici_conn_t *conn)
{
	bool raw = FALSE;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'r':
				raw = TRUE;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --log option");
		}
		break;
	}

	if (vici_register(conn, "log", log_cb, &raw) != 0)
	{
		fprintf(stderr, "registering for log failed: %s\n", strerror(errno));
		return errno;
	}
	while (TRUE)
	{
		sleep(1);
	}
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		logcmd, 'T', "log", "trace logging output",
		{"[--raw]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
		}
	});
}
