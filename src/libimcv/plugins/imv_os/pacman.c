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
#include <time.h>

#include "imv_os_state.h"

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
		   "ipsec pacman --product <name> --file <filename> [--update]\n");
}

/**
 * Extract the time the package file was generated
 */
static time_t extract_time(char *line)
{
	struct tm t;
	char wday[4], mon[4];
	char* months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
					   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	int i;

	if (sscanf(line, "Generated: %3s %3s %2d %2d:%2d:%2d %4d UTC", wday, mon,
			   &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_year) != 7)
	{
		return UNDEFINED_TIME;
	}
	t.tm_isdst = 0;
	t.tm_year -= 1900;
	t.tm_mon = 12;

	for (i = 0; i < countof(months); i++)
	{
		if (streq(mon, months[i]))
		{
			t.tm_mon = i;
			break;
		}
	}
	if (t.tm_mon == 12)
	{
		return UNDEFINED_TIME;
	}

	return mktime(&t) - timezone;
}

/**
 * Process a package file and store updates in the database
 */
static void process_packages(char *filename, char *product, bool update)
{
	char *uri, line[12288], *pos;
	int count = 0, errored = 0, vulnerable = 0, new_packages = 0;
	int new_versions = 0, updated_versions = 0, deleted_versions = 0;
	time_t gen_time;
	u_int32_t pid = 0;
	enumerator_t *e;
	database_t *db;
	FILE *file;

	/* opening package file */
	printf("loading\"%s\"\n", filename);
	file = fopen(filename, "r");
	if (!file)
	{
		fprintf(stderr, "could not open \"%s\"\n", filename);
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
		char *cur_version, *version_update = NULL, *version_delete = NULL;
		bool security, add_version = TRUE;
		int cur_security, security_update = 0, security_delete = 0;
		u_int32_t gid = 0, vid = 0, vid_update = 0, vid_delete = 0;
		time_t cur_time;

		count++;
		if (count == 1)
		{
			printf("%s", line);
		}
		if (count == 3)
		{
			gen_time = extract_time(line);

			if (gen_time == UNDEFINED_TIME)
			{
				fprintf(stderr, "could not extract generation time\n");
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			printf("Generated: %T\n", &gen_time, TRUE);
		}
		if (count < 7)
		{
			continue;
		}

		/* look for the package name */
		pos = strchr(line, ' ');
		if (!pos)
		{
			fprintf(stderr, "could not extract package name from '%.*s'\n",
					(int)(strlen(line)-1), line);
			errored++;
			continue;
		}
		*pos++ = '\0';
		package = line;

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
				fprintf(stderr, "could not extract package version from "
						"'%.*s'\n", (int)(strlen(line)-1), line);
				errored++;
				continue;
			}
		}
		else
		{
			/* no version information, skip entry */
			continue;
		}
		security = (strstr(pos, "[security]") != NULL);
		if (security)
		{
			vulnerable++;
		}

		/* handle non-security packages in update mode only */
		if (!update && !security)
		{
			continue;
		}

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
		if (!gid && security)
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

		/* check for package versions already in database */
		e = db->query(db,
				"SELECT id, release, security, time FROM versions "
				"WHERE package = ? AND product = ?",
				DB_INT, gid, DB_INT, pid, DB_INT, DB_TEXT, DB_INT, DB_INT);
		if (!e)
		{
			break;
		}
		while (e->enumerate(e, &vid, &cur_version, &cur_security, &cur_time))
		{
			if (streq(version, cur_version))
			{
				/* already in data base */
				add_version = FALSE;
				break;
			}
			else if (gen_time > cur_time)
			{
				if (security)
				{
					if (cur_security)
					{
						vid_update = vid;
						version_update = strdup(cur_version);
						security_update = cur_security;
					}
					else
					{
						vid_delete = vid;
						version_delete = strdup(cur_version);
						security_delete = cur_security;
					}
				}
				else
				{
					if (!cur_security)
					{
						vid_update = vid;
						version_update = strdup(cur_version);
						security_update = cur_security;
					}
				}
			}
			else
			{
				if (security == cur_security)
				{
					add_version = FALSE;
				}
			}
		}
		e->destroy(e);

		if ((!vid && !security) || (vid && !add_version))
		{
			free(version_update);
			free(version_delete);
			continue;
		}

		if ((!vid && security) || (vid && !vid_update))
		{
			printf("%s (%s) %s\n", package, version, security ? "[s]" : "");

			if (db->execute(db, &vid,
				"INSERT INTO versions "
				"(package, product, release, security, time) "
				"VALUES (?, ?, ?, ?, ?)", DB_INT, gid, DB_INT, pid,
				DB_TEXT, version, DB_INT, security, DB_INT, gen_time) != 1)
			{
				fprintf(stderr, "could not store version '%s' to database\n",
								 version);
				free(version_update);
				free(version_delete);
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			new_versions++;
		}
		else
		{
			printf("%s (%s) %s updated by\n",
				   package, version_update, security_update ? "[s]" : "");
			printf("%s (%s) %s\n", package, version, security ? "[s]" : "");

			if (db->execute(db, NULL,
				"UPDATE versions SET release = ?, time = ? WHERE id = ?",
				DB_TEXT, version, DB_INT, gen_time, DB_INT, vid_update) <= 0)
			{
				fprintf(stderr, "could not update version '%s' to database\n",
								 version);
				free(version_update);
				free(version_delete);
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			updated_versions++;
		}

		if (vid_delete)
		{
			printf("%s (%s) %s deleted\n",
				   package, version_delete, security_delete ? "[s]" : "");

			if (db->execute(db, NULL,
				"DELETE FROM  versions WHERE id = ?",
				DB_INT, vid_delete) <= 0)
			{
				fprintf(stderr, "could not delete version '%s' from database\n",
								 version_delete);
				free(version_update);
				free(version_delete);
				fclose(file);
				db->destroy(db);
				exit(EXIT_FAILURE);
			}
			deleted_versions++;
		}
		free(version_update);
		free(version_delete);
	}
	fclose(file);
	db->destroy(db);

	printf("processed %d packages, %d security, %d new packages, "
		   "%d new versions, %d updated versions, %d deleted versions, "
		   "%d errored\n", count - 6, vulnerable, new_packages, new_versions,
		   updated_versions, deleted_versions, errored);
}

static void do_args(int argc, char *argv[])
{
	char *filename = NULL, *product = NULL;
	bool update = FALSE;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "file", required_argument, NULL, 'f' },
			{ "product", required_argument, NULL, 'p' },
			{ "update", no_argument, NULL, 'u' },
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
			case 'u':
				update = TRUE;
				continue;
		}
		break;
	}

	if (filename && product)
	{
		process_packages(filename, product, update);
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

