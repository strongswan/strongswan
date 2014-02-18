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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>

#include "command.h"

/**
 * Check if we should handle a key as a list of comma separated values
 */
static bool is_list_key(char *key)
{
	char *keys[] = {
		"local_addrs",
		"remote_addrs",
		"proposals",
		"esp_proposals",
		"ah_proposals",
		"local_ts",
		"remote_ts",
		"vips",
	};
	int i;

	for (i = 0; i < countof(keys); i++)
	{
		if (strcaseeq(keys[i], key))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Add a vici list from a comma separated string value
 */
static void add_list_key(vici_req_t *req, char *key, char *value)
{
	enumerator_t *enumerator;
	char *token;

	vici_begin_list(req, key);
	enumerator = enumerator_create_token(value, ",", " ");
	while (enumerator->enumerate(enumerator, &token))
	{
		vici_add_list_itemf(req, "%s", token);
	}
	enumerator->destroy(enumerator);
	vici_end_list(req);
}

/**
 * Translate setting key/values from a section into vici key-values/lists
 */
static void add_key_values(vici_req_t *req, settings_t *cfg, char *section)
{
	enumerator_t *enumerator;
	char *key, *value;

	enumerator = cfg->create_key_value_enumerator(cfg, section);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		if (is_list_key(key))
		{
			add_list_key(req, key, value);
		}
		else
		{
			vici_add_key_valuef(req, key, "%s", value);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Translate a settings section to a vici section
 */
static void add_sections(vici_req_t *req, settings_t *cfg, char *section)
{
	enumerator_t *enumerator;
	char *name, buf[256];

	enumerator = cfg->create_section_enumerator(cfg, section);
	while (enumerator->enumerate(enumerator, &name))
	{
		vici_begin_section(req, name);
		snprintf(buf, sizeof(buf), "%s.%s", section, name);
		add_key_values(req, cfg, buf);
		add_sections(req, cfg, buf);
		vici_end_section(req);
	}
	enumerator->destroy(enumerator);
}

/**
 * Load an IKE_SA config with CHILD_SA configs from a section
 */
static bool load_conn(vici_conn_t *conn, settings_t *cfg,
					  char *section, bool raw)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;
	char buf[128];

	snprintf(buf, sizeof(buf), "%s.%s", "connections", section);

	req = vici_begin("load-conn");

	vici_begin_section(req, section);
	add_key_values(req, cfg, buf);
	add_sections(req, cfg, buf);
	vici_end_section(req);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "load-conn request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (raw)
	{
		vici_dump(res, "load-conn reply", stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading connection '%s' failed: %s\n",
				section, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	vici_free_res(res);
	return ret;
}

CALLBACK(list_conn, int,
	linked_list_t *list, vici_res_t *res, char *name, void *value, int len)
{
	if (streq(name, "conns"))
	{
		char *str;

		if (asprintf(&str, "%.*s", len, value) != -1)
		{
			list->insert_last(list, str);
		}
	}
	return 0;
}

/**
 * Create a list of currently loaded connections
 */
static linked_list_t* list_conns(vici_conn_t *conn, bool raw)
{
	linked_list_t *list;
	vici_res_t *res;

	list = linked_list_create();

	res = vici_submit(vici_begin("get-conns"), conn);
	if (res)
	{
		if (raw)
		{
			vici_dump(res, "get-conns reply", stdout);
		}
		vici_parse_cb(res, NULL, NULL, list_conn, list);
		vici_free_res(res);
	}
	return list;
}

/**
 * Remove and free a string from a list
 */
static void remove_from_list(linked_list_t *list, char *str)
{
	enumerator_t *enumerator;
	char *current;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current, str))
		{
			list->remove_at(list, enumerator);
			free(current);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Unload a connection by name
 */
static bool unload_conn(vici_conn_t *conn, char *name, bool raw)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;

	req = vici_begin("unload-conn");
	vici_add_key_valuef(req, "name", "%s", name);
	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "unload-conn request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (raw)
	{
		vici_dump(res, "unload-conn reply", stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "unloading connection '%s' failed: %s\n",
				name, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	vici_free_res(res);
	return ret;
}

static int load_conns(vici_conn_t *conn)
{
	bool raw = FALSE;
	u_int found = 0, loaded = 0, unloaded = 0;
	char *arg, *section;
	enumerator_t *enumerator;
	linked_list_t *conns;
	settings_t *cfg;

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
				return command_usage("invalid --load-conns option");
		}
		break;
	}

	cfg = settings_create(CONF_FILE);
	if (!cfg)
	{
		fprintf(stderr, "parsing '%s' failed\n", CONF_FILE);
		return EINVAL;
	}

	conns = list_conns(conn, raw);

	enumerator = cfg->create_section_enumerator(cfg, "connections");
	while (enumerator->enumerate(enumerator, &section))
	{
		remove_from_list(conns, section);
		found++;
		if (load_conn(conn, cfg, section, raw))
		{
			loaded++;
		}
	}
	enumerator->destroy(enumerator);

	cfg->destroy(cfg);

	/* unload all connection in daemon, but not in file */
	while (conns->remove_first(conns, (void**)&section) == SUCCESS)
	{
		if (unload_conn(conn, section, raw))
		{
			unloaded++;
		}
		free(section);
	}
	conns->destroy(conns);

	if (raw)
	{
		return 0;
	}
	if (found == 0)
	{
		printf("no connections found, %u unloaded\n", unloaded);
		return 0;
	}
	if (loaded == found)
	{
		printf("successfully loaded %u connections, %u unloaded\n",
			   loaded, unloaded);
		return 0;
	}
	fprintf(stderr, "loaded %u of %u connections, %u failed to load, "
			"%u unloaded\n", loaded, found, found - loaded, unloaded);
	return EINVAL;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		load_conns, 'c', "load-conns", "(re-)load connection configuration",
		{"[--raw]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
		}
	});
}
