/*
 * Copyright (C) 2016 Fu Xiaoqiang
 * Nokia

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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>

#include "command.h"

#include <collections/hashtable.h>

/**
 * Free hashtable with contained strings
 */
static void free_hashtable(hashtable_t *hashtable)
{
	enumerator_t *enumerator;
	char *str;

	enumerator = hashtable->create_enumerator(hashtable);
	while (enumerator->enumerate(enumerator, NULL, &str))
	{
		free(str);
	}
	enumerator->destroy(enumerator);

	hashtable->destroy(hashtable);
}

CALLBACK(sa_values, int,
	hashtable_t *sa, vici_res_t *res, char *name, void *value, int len)
{
	chunk_t chunk;
	char *str;

	chunk = chunk_create(value, len);
	if (chunk_printable(chunk, NULL, ' '))
	{
		if (asprintf(&str, "%.*s", len, value) >= 0)
		{
			free(sa->put(sa, name, str));
		}
	}
	return 0;
}


CALLBACK(sa_list, int,
	hashtable_t *sa, vici_res_t *res, char *name, void *value, int len)
{
	chunk_t chunk;
	char *str;

	chunk = chunk_create(value, len);
	if (chunk_printable(chunk, NULL, ' '))
	{
		str = sa->get(sa, name);
		if (asprintf(&str, "%s%s%.*s",
					 str ?: "", str ? " " : "", len, value) >= 0)
		{
			free(sa->put(sa, name, str));
		}
	}
	return 0;
}

CALLBACK(conn_reqid, int,
	hashtable_t *ike, vici_res_t *res, char *name)
{
	hashtable_t *child;
	int ret;

	child = hashtable_create(hashtable_hash_str, hashtable_equals_str, 1);
	ret = vici_parse_cb(res, NULL, sa_values, sa_list, child);
	if (ret == 0)
	{
		printf("%s: reqid %s", name, child->get(child, "reqid"));
		printf("\n");
	}
	free_hashtable(child);
	return ret;
}

CALLBACK(ike_sa, int,
	hashtable_t *ike, vici_res_t *res, char *name)
{
	if (streq(name, "child-sas"))
	{
		return vici_parse_cb(res, conn_reqid, NULL, NULL, ike);
	}
	return 0;
}

CALLBACK(ike_sas, int,
	void *null, vici_res_t *res, char *name)
{
	hashtable_t *ike;
	int ret;

	ike = hashtable_create(hashtable_hash_str, hashtable_equals_str, 1);
	ike->put(ike, "name", strdup(name));
	ret = vici_parse_cb(res, ike_sa, sa_values, sa_list, ike);
	free_hashtable(ike);
	return ret;
}

CALLBACK(list_cb, void,
	command_format_options_t *format, char *name, vici_res_t *res)
{
	char buf[256];

	if (*format & COMMAND_FORMAT_RAW)
	{
		snprintf(buf, sizeof(buf), "%s event", name);
		vici_dump(res, buf, *format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else
	{
		if (vici_parse_cb(res, ike_sas, NULL, NULL, NULL) != 0)
		{
			fprintf(stderr, "parsing SA event failed: %s\n", strerror(errno));
		}
	}
}

static int list_conn_reqid(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	bool noblock = FALSE;
	command_format_options_t format = COMMAND_FORMAT_NONE;
	char *arg, *ike = NULL;
	int ike_id = 0, ret;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'n':
				noblock = TRUE;
				continue;
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --list-conn-reqid option");
		}
		break;
	}
	if (vici_register(conn, "list-sa", list_cb, &format) != 0)
	{
		ret = errno;
		fprintf(stderr, "registering for SAs failed: %s\n", strerror(errno));
		return ret;
	}
	req = vici_begin("list-sas");
	if (ike)
	{
		vici_add_key_valuef(req, "ike", "%s", ike);
	}
	if (ike_id)
	{
		vici_add_key_valuef(req, "ike-id", "%d", ike_id);
	}
	if (noblock)
	{
		vici_add_key_valuef(req, "noblock", "yes");
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "list-conn-reqid request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "list-conn-reqid reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	vici_free_res(res);
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		list_conn_reqid, 'C', "list-conn-reqid",
		"list currently active connection name and reqid map",
		{"[--raw|--pretty]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
		}
	});
}
