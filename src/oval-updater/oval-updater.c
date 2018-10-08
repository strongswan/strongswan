/*
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>

#include <library.h>
#include <utils/debug.h>
#include <collections/hashtable.h>
#include <collections/array.h>

#include <libxml/parser.h>

#include "oval.h"

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = FALSE;

/**
 * oval_updater dbg function
 */
static void oval_updater_dbg(debug_t group, level_t level, char *fmt, ...)
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
 * atexit handler to close everything on shutdown
 */
static void cleanup(void)
{
	closelog();
	library_deinit();
}

static void usage(void)
{
	printf("\
Usage:\n\
  oval-updater --help\n\
  oval-updater [--debug <level>] [--quiet]  --os <string> --archs <string> \n\
                --file <filename>\n\n\
  Options:\n\
    --help             print usage information\n\
    --debug <level>    set debug level\n\
    --quiet            suppress debug output to stderr\n\
    --os <string>      operating system\n\
    --archs <string>   space separated enumeration of architectures\n\
    --file <filename>  oval definition file\n");
 }

/**
 * global objects
 */
hashtable_t *tests, *objects, *states;
database_t *db;

static void extract_criteria(oval_t *oval, xmlNodePtr node)
{
	xmlNodePtr cur, c, tst, ste, s;

	for (c = node->xmlChildrenNode; c != NULL; c = c->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(c))
		{
			continue;
		}
		if (!xmlStrcmp(c->name, "criterion"))
		{
			enumerator_t *e;
			char *test_ref = NULL, *obj_ref = NULL, *state_ref = NULL;
			char *obj_name = NULL, *op = NULL, *version = NULL;
			int obj_id = 0;

			test_ref = xmlGetProp(c, "test_ref");

			tst = tests->get(tests, test_ref);
			if (tst)
			{
				for (cur = tst->xmlChildrenNode; cur != NULL; cur = cur->next)
				{
					/* ignore empty or blank nodes */
					if (xmlIsBlankNode(cur))
					{
						continue;
					}
					if (!xmlStrcmp(cur->name, "object"))
					{
						obj_ref = xmlGetProp(cur, "object_ref");
						obj_name = objects->get(objects, obj_ref);
						if (obj_name)
						{
							/* check if object is already in database */
							e = db->query(db, "SELECT id FROM packages WHERE "
										"name = ?", DB_TEXT, obj_name, DB_INT);
							if (e)
							{
								if (!e->enumerate(e, &obj_id))
								{
									obj_id = 0;
								}
								e->destroy(e);
							}
						}
					}
					else if (!xmlStrcmp(cur->name, "state"))
					{
						state_ref = xmlGetProp(cur, "state_ref");

						ste = states->get(states, state_ref);
						if (ste)
						{
							for (s = ste->xmlChildrenNode; s != NULL; s = s->next)
							{
								if (!xmlStrcmp(s->name, "evr"))
								{
									op = xmlGetProp(s, "operation");
									version = xmlNodeGetContent(s);
								}
							}
						}
					}
				}
			}
			oval->add_criterion(oval, test_ref, state_ref, obj_ref, obj_name,
								obj_id, op, version);
		}
		else if (!xmlStrcmp(c->name, "criteria"))
		{
			extract_criteria(oval, c);
		}
	}
}

bool is_vulnerable(array_t *products, int pid, char *release, char *version)
{
	char command[BUF_LEN];
	int i, product_id;

	for (i = 0; i < array_count(products); i++)
	{
		if (array_get(products, i, &product_id) && product_id == pid)
		{
			snprintf(command, BUF_LEN, "dpkg --compare-versions %s lt %s",
										release, version);
			return system(command) == 0;
		}
	}
	return FALSE;
}

/**
 * Process an OVAL definition file
 */
static int process_oval_file(char *path, char *os, char *archs)
{
	xmlDocPtr doc;
	xmlNodePtr defs = NULL, objs = NULL, tsts = NULL, stes = NULL;
	xmlNodePtr cur, def, tst, obj, ste, c;
	oval_t *oval = NULL;
	enumerator_t *e;
	array_t *products;
	char *db_uri, *cve_ref, *description, *title, *start, *stop;
	uint32_t def_count = 0, tst_count = 0, obj_count = 0, ste_count = 0;
	uint32_t complete_count = 0;
	int pid = 0, result = EXIT_FAILURE;

    xmlInitParser();

	/* parsing OVAL XML file */
	doc = xmlReadFile(path, NULL, 0);
	if (!doc)
	{
		DBG1(DBG_LIB, "  could not be parsed \"%s\"", path);
		goto end;
	}

	/* check out the XML document */
	cur = xmlDocGetRootElement(doc);
	if (!cur)
	{
		DBG1(DBG_LIB, "  empty OVAL document");
		goto end;
	}
	if (xmlStrcmp(cur->name, "oval_definitions"))
	{
		DBG1(DBG_LIB, "  no oval_definitions element found");
		goto end;
	}

	/* Now walk the tree, handling nodes as we go */
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(cur))
		{
			continue;
		}
		if (!xmlStrcmp(cur->name, "definitions"))
		{
			defs = cur;
		}
		else if (!xmlStrcmp(cur->name, "objects"))
		{
			objs = cur;
		}
		else if(!xmlStrcmp(cur->name, "tests"))
		{
			tsts = cur;
		}
		else if (!xmlStrcmp(cur->name, "states"))
		{
			stes = cur;
		}
	}

	if (!defs || !objs || !tsts || !stes)
	{
		if (!defs)
		{
			DBG1(DBG_LIB, "  no definitions element found");
		}
		if (!objs)
		{
			DBG1(DBG_LIB, "  no objects element found");
		}
		if (!tsts)
		{
			DBG1(DBG_LIB, "  no tests element found");
		}
		if (!stes)
		{
			DBG1(DBG_LIB, "  no states element found");
		}
		goto end;
	}

	/* connect package database */
	db_uri = lib->settings->get_str(lib->settings, "oval-updater.database", NULL);
	if (!db_uri)
	{
		DBG1(DBG_LIB, "database URI sec-updater.database not set");
		goto end;
	}
	db = lib->db->create(lib->db, db_uri);
	if (!db)
	{
		DBG1(DBG_LIB, "could not connect to database '%s'", db_uri);
		goto end;
	}

	/* check if architectures of a given os are already in database */
	products = array_create(sizeof(int), 5);
	start = archs;

	while (TRUE)
	{
		char product[32];

		stop = strchrnul(start, ' ');
		if (stop == NULL)
		{
			break;
		}
		snprintf(product, sizeof(product), "%s %.*s", os, stop - start, start);

		e = db->query(db, "SELECT id FROM products WHERE name = ?",
						  DB_TEXT, product, DB_INT);
		if (e)
		{
			if (e->enumerate(e, &pid))
			{
				array_insert(products, -1, &pid);
				DBG1(DBG_LIB, "%s (%d)", product, pid);
			}
			e->destroy(e);
		}
		if (*stop == '\0')
		{
			break;
		}
		start = stop + 1;
	}

	/* create tests hash table for fast access */
	tests = hashtable_create(hashtable_hash_str, hashtable_equals_str, 32768);

	/* enumerate tests */
	for (tst = tsts->xmlChildrenNode; tst != NULL; tst = tst->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(tst))
		{
			continue;
		}
		if (!xmlStrcmp(tst->name, "dpkginfo_test"))
		{
			tests->put(tests, xmlGetProp(tst, "id"), tst);
			tst_count++;
		}
	}
	DBG1(DBG_LIB, "%u tests", tst_count);

	/* create objects hash table for fast access */
	objects = hashtable_create(hashtable_hash_str, hashtable_equals_str, 4096);

	/* enumerate objects */
	for (obj = objs->xmlChildrenNode; obj != NULL; obj = obj->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(obj))
		{
			continue;
		}
		if (!xmlStrcmp(obj->name, "dpkginfo_object"))
		{
			for (cur = obj->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				/* ignore empty or blank nodes */
				if (xmlIsBlankNode(cur))
				{
					continue;
				}
				if (!xmlStrcmp(cur->name, "name"))
				{
					objects->put(objects, xmlGetProp(obj, "id"),
										  xmlNodeGetContent(cur));
					obj_count++;
				}
			}
		}
	}
	DBG1(DBG_LIB, "%u objects", obj_count);

	/* create states hash table for fast access */
	states = hashtable_create(hashtable_hash_str, hashtable_equals_str, 16384);

	/* enumerate states */
	for (ste = stes->xmlChildrenNode; ste != NULL; ste = ste->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(ste))
		{
			continue;
		}
		if (!xmlStrcmp(ste->name, "dpkginfo_state"))
		{
			states->put(states, xmlGetProp(ste, "id"), ste);
			ste_count++;
		}
	}
	DBG1(DBG_LIB, "%u states", ste_count);

	/* enumerate definitions */
	for (def = defs->xmlChildrenNode; def != NULL; def = def->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(def))
		{
			continue;
		}
		if (!xmlStrcmp(def->name, "definition") &&
			!xmlStrcmp(xmlGetProp(def, "class"), "vulnerability"))
		{
			cve_ref = description = title = NULL;

			for (cur = def->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				/* ignore empty or blank nodes */
				if (xmlIsBlankNode(cur))
				{
					continue;
				}
				if (!xmlStrcmp(cur->name, "metadata"))
				{
					for (c = cur->xmlChildrenNode; c != NULL; c = c->next)
					{
						/* ignore empty or blank nodes */
						if (xmlIsBlankNode(c))
						{
							continue;
						}
						if (!xmlStrcmp(c->name, "reference"))
						{
							cve_ref = xmlGetProp(c, "ref_id");
						}
						else if (!xmlStrcmp(c->name, "description"))
						{
							description = xmlNodeGetContent(c);
						}
						else if (!xmlStrcmp(c->name, "title"))
						{
							title = xmlNodeGetContent(c);
						}
					}
					if (cve_ref || title)
					{
						if (!cve_ref)
						{
							cve_ref = title;
						}
						def_count++;
					}
					oval = oval_create(cve_ref, description);
				}
				else if (!xmlStrcmp(cur->name, "criteria"))
				{
					extract_criteria(oval, cur);
				}
			}
		}
		if (oval)
		{
			oval->print(oval);

			if (oval->is_complete(oval))
			{
				enumerator_t *enumerator;
				char *obj_name, *version, *release;
				int obj_id, vid, pid, security;

				enumerator = oval->create_criterion_enumerator(oval);
				while (enumerator->enumerate(enumerator, &obj_name, &obj_id,
											 			 &version))
				{
					e = db->query(db, "SELECT id, product, release, security "
						"FROM versions WHERE package = ?", DB_INT, obj_id,
						DB_INT, DB_INT, DB_TEXT, DB_INT);
					if (e)
					{
						while (e->enumerate(e, &vid, &pid, &release, &security))
						{
							if (is_vulnerable(products, pid, release, version))
							{
								DBG1(DBG_LIB, "xxx%-14s %s %s (%d) %s (%d, %d)",
									 cve_ref, security ? "*" : " ",
									 obj_name, obj_id, release, pid, vid);
							}
						}
						e->destroy(e);
					}
				}
				enumerator->destroy(enumerator);
				complete_count++;
			}
			oval->destroy(oval);
			oval = NULL;
		}
	}
	DBG1(DBG_LIB, "%u of %u definitions are complete", complete_count, def_count);

	db->destroy(db);
	tests->destroy(tests);
	objects->destroy(objects);
	states->destroy(states);
	xmlFreeDoc(doc);
	result = EXIT_SUCCESS;

end:
	xmlCleanupParser();
	return result;
}

static int do_args(int argc, char *argv[])
{
	char *filename = NULL, *os = NULL, *archs = NULL;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "debug", required_argument, NULL, 'd' },
			{ "file", required_argument, NULL, 'f' },
			{ "os", required_argument, NULL, 'o' },
			{ "archs", required_argument, NULL, 'a' },
			{ "quiet", no_argument, NULL, 'q' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "hd:f:o:a:q", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'd':
				debug_level = atoi(optarg);
				continue;
			case 'f':
				filename = optarg;
				continue;
			case 'o':
				os = optarg;
				continue;
			case 'a':
				archs = optarg;
				continue;
			case 'q':
				stderr_quiet = TRUE;
				continue;
		}
		break;
	}

	if (filename && os && archs)
	{
		return process_oval_file(filename, os, archs);
	}
	else
	{
		usage();
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	/* enable attest debugging hook */
	dbg = oval_updater_dbg;
	openlog("oval-updater", 0, LOG_DEBUG);

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL, "oval-updater"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "oval-updater.load",
												  "sqlite curl")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	exit(do_args(argc, argv));
}
