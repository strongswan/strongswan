/*
 * Copyright (C) 2012 Andreas Steffen
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

#include <library.h>
#include <utils/debug.h>

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = TRUE;

/**
 * pacman dbg function
 */
static void pacman_dbg(debug_t group, level_t level, char *fmt, ...)
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
 	printf("Usage:\n"
		   "ipsec pacman --file <filename> --package <name>\n");
}

/**
 * Process a package file and store updates in the database
 */
static void process_packages(char *filename, char *product)
{
	char *uri, line[1024], *pos;
	int count = 0, errored = 0, vulnerable = 0;
	int new_packages = 0, new_versions = 0, updates = 0, reverted = 0;
	u_int32_t pid = 0;
	enumerator_t *e;
	database_t *db;
	FILE *file;

	/* opening package file */
	printf("loading\"%s\"\n", filename);
	file = fopen(filename, "r");
	if (!file)
	{
		fprintf(stderr, "could not open \"%s\"", filename);
		exit(EXIT_FAILURE);
	}

	/* connect package database */
	uri = lib->settings->get_str(lib->settings, "pacman.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "database URI pacman.database not set\n");
		fclose(file);
		exit(EXIT_FAILURE);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "could not connect to database '%s'\n", uri);
		fclose(file);
		exit(EXIT_FAILURE);
	}

	/* check if product is already in database */
	e = db->query(db, "SELECT id FROM products WHERE name = ?",
				  DB_TEXT, product, DB_INT);
	if (e)
	{
		if (!e->enumerate(e, &pid))
		{
			pid = 0;
		}
		e->destroy(e);
	}
	if (!pid)
	{	
		if (db->execute(db, &pid, "INSERT INTO products (name) VALUES (?)",
						DB_TEXT, product) != 1)
		{
			fprintf(stderr, "could not store product '%s' to database\n",
							 product);
			fclose(file);
			db->destroy(db);
			exit(EXIT_FAILURE);
		}
	}

	while (fgets(line, sizeof(line), file))
	{
		char *package, *version;
		bool security;
		int current_security;
		u_int32_t gid = 0, vid = 0;

		count++;
		if (count == 1 || count == 3)
		{
			printf("%s", line);
		}
		if (count < 7)
		{
			continue;
		}

		/* look for the package name */
		pos = strchr(line, ' ');
		if (!pos)
		{
			fprintf(stderr, "could not extract package name from '%.*s'",
					strlen(line)-1, line);
			errored++;
			continue;
		}
		*pos++ = '\0';
		package = line;
		version = "";

		/* check if package is already in database */
		e = db->query(db, "SELECT id FROM packages WHERE name = ?",
						  DB_TEXT, package, DB_INT);
		if (e)
		{
			if (!e->enumerate(e, &gid))
			{
				gid = 0;
			}
			e->destroy(e);
		}
		if (!gid)
		{	
			if (db->execute(db, &gid, "INSERT INTO packages (name) VALUES (?)",
								DB_TEXT, package) != 1)
			{
				fprintf(stderr, "could not store package '%s' to database\n",
								 package);
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			new_packages++;
		}

		/* look for version string in parentheses */
		if (*pos == '(')
		{
			version = ++pos;
			pos = strchr(pos, ')');
			if (pos)
			{
				*pos++ = '\0'; 
			}
			else
			{
				fprintf(stderr, "could not extract package version from '%.*s'",
					strlen(line)-1, line);
				errored++;
				continue;
			}
		}
		security = (strstr(pos, "[security]") != NULL);
		if (security)
		{
			vulnerable++;
		}

		/* check if version is already in database */
		e = db->query(db, "SELECT id, security FROM versions "
						  "WHERE release = ? AND package = ? AND product = ?",
					  	  DB_TEXT, version, DB_INT, pid, DB_INT, gid,
						  DB_INT, DB_INT);
		if (e)
		{
			if (!e->enumerate(e, &vid, &current_security))
			{
				vid = 0;
			}
			e->destroy(e);
		}
		if (!vid)
		{	
			if (db->execute(db, &gid,
				"INSERT INTO versions (package, product, release, security) "
				"VALUES (?, ?, ?, ?)", DB_INT, gid, DB_INT, pid,
				DB_TEXT, version, DB_INT, security) != 1)
			{
				fprintf(stderr, "could not store version '%s' to database\n",
								 version);
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			new_versions++;
		}
		else if (current_security != security)
		{
			printf("'%s' (%s) %s\n", package, version, security ? "[s]" : "");

			if (security)
			{
				if (db->execute(db, NULL,
					"UPDATE versions SET security = ? WHERE vid = ?",
					DB_INT, security, DB_INT, vid)  < 0)
				{
					fprintf(stderr, "could not store update security field\n");
					fclose(file);
					db->destroy(db);
					exit(EXIT_FAILURE);
				}
				updates++;
			}
			else
			{
				reverted++;
			}
		}							
	}

	fclose(file);
	db->destroy(db);
	printf("processed %d packages, %d vulnerable, %d errored, "
		   "%d new packages, %d new versions, %d updates, %d reverted\n",
			count - 6, vulnerable, errored, new_packages, new_versions,
			updates, reverted);	
}

static void do_args(int argc, char *argv[])
{
	char *filename = NULL, *product = NULL;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "file", required_argument, NULL, 'f' },
			{ "product", required_argument, NULL, 'p' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				filename = optarg;
				continue;
			case 'p':
				product = optarg;
				continue;
		}
		break;
	}

	if (filename && product)
	{
		process_packages(filename, product);
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
	dbg = pacman_dbg;
	openlog("pacman", 0, LOG_DEBUG);

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "attest.load", "sqlite")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	do_args(argc, argv);

	exit(EXIT_SUCCESS);
}

