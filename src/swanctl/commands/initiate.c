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

/*
 * Copyright (C) 2014 Timo Teräs <timo.teras@iki.fi>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "command.h"

#include <errno.h>

CALLBACK(log_cb, void,
	command_format_options_t *format, char *name, vici_res_t *msg)
{
	if (*format & COMMAND_FORMAT_RAW)
	{
		vici_dump(msg, "log", *format & COMMAND_FORMAT_PRETTY, stdout);
	}
	else
	{
		printf("[%s] %s\n",
			   vici_find_str(msg, "   ", "group"),
			   vici_find_str(msg, "", "msg"));
	}
}

static int initiate(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	command_format_options_t format = COMMAND_FORMAT_NONE;
	char *arg, *child = NULL, *ike = NULL, *my_host = NULL, *other_host = NULL;
	int ret = 0, timeout = 0, level = 1;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case 'c':
				child = arg;
				continue;
			case 'i':
				ike = arg;
				continue;
			case 't':
				timeout = atoi(arg);
				continue;
			case 'l':
				level = atoi(arg);
				continue;
			case 's':
				my_host = arg;
				continue;
			case 'd':
				other_host = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --initiate option");
		}
		break;
	}

	if (vici_register(conn, "control-log", log_cb, &format) != 0)
	{
		ret = errno;
		fprintf(stderr, "registering for log failed: %s\n", strerror(errno));
		return ret;
	}
	req = vici_begin("initiate");
	if (child)
	{
		vici_add_key_valuef(req, "child", "%s", child);
	}
	if (ike)
	{
		vici_add_key_valuef(req, "ike", "%s", ike);
	}
	if (my_host)
	{
		vici_add_key_valuef(req, "my-host", "%s", my_host);
	}
	if (other_host)
	{
		vici_add_key_valuef(req, "other-host", "%s", other_host);
	}
	if (timeout)
	{
		vici_add_key_valuef(req, "timeout", "%d", timeout * 1000);
	}
	vici_add_key_valuef(req, "loglevel", "%d", level);
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "initiate request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "initiate reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else
	{
		if (streq(vici_find_str(res, "no", "success"), "yes"))
		{
			printf("initiate completed successfully\n");
		}
		else
		{
			fprintf(stderr, "initiate failed: %s\n",
					vici_find_str(res, "", "errmsg"));
			ret = 1;
		}
	}
	vici_free_res(res);
	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		initiate, 'i', "initiate", "initiate a connection",
		{"[--child <name>] [--ike <name>] [--timeout <s>] [--raw|--pretty]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"child",		'c', 1, "initiate a CHILD_SA configuration"},
			{"ike",			'i', 1, "initiate an IKE_SA, or name of child's parent"},
			{"source",		's', 1, "override source address"},
			{"remote",		'd', 1, "override remote address"},
			{"timeout",		't', 1, "timeout in seconds before detaching"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"loglevel",	'l', 1, "verbosity of redirected log"},
		}
	});
}
