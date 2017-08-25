/*
 * Copyright (C) 2012-2017 Andreas Steffen
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
#include <sys/stat.h>
#include <stdlib.h>

#include <library.h>
#include <utils/debug.h>

typedef enum sec_update_state_t sec_update_state_t;

enum sec_update_state_t {
	SEC_UPDATE_STATE_BEGIN_PACKAGE,
	SEC_UPDATE_STATE_VERSION,
	SEC_UPDATE_STATE_END_PACKAGE
};

typedef struct stats_t stats_t;

struct stats_t {
	time_t release;
	int product;
	int packages;
	int new_versions;
	int updated_versions;
};

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = FALSE;

/**
 * sec_updater dbg function
 */
static void sec_updater_dbg(debug_t group, level_t level, char *fmt, ...)
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
  sec-updater --help\n\
  sec-updater [--debug <level>] [--quiet]  [--security] --product <name> --file <filename>\n\n\
  Options:\n\
    --help             print usage information\n\
    --debug            set debug level\n\
    --quiet            suppress debug output to stderr\n\
    --security         set when parsing a file with security updates\n\
    --product <name>   name of the Linux version as stored in the database\n\
    --file <filename>  package information file to parse");
}

/**
 * Update the package database
 */
static bool update_database(database_t *db, char *package, char *version,
							bool security, stats_t *stats)
{
	int pid = 0, vid = 0, sec_flag;
	bool first = TRUE, found = FALSE;
	char *release;
	enumerator_t *e;

	/* increment package count */
	stats->packages++;

	/* check if package is already in database */
	e = db->query(db, "SELECT id FROM packages WHERE name = ?",
					  DB_TEXT, package, DB_INT);
	if (!e)
	{
		return FALSE;
	}
	if (!e->enumerate(e, &pid))
	{
		pid = 0;
	}
	e->destroy(e);

	if (!pid)
	{
		return TRUE;
	}

	/* retrieve all package versions stored in database */
	e = db->query(db,
			"SELECT id, release, security FROM versions "
			"WHERE product = ? AND package = ?",
			 DB_INT, stats->product,  DB_INT, pid, DB_INT, DB_TEXT, DB_INT);
	if (!e)
	{
		return FALSE;
	}

	while (e->enumerate(e, &vid, &release, &sec_flag))
	{
		char command[BUF_LEN];
		char found_char = ' ';
		bool update_version = FALSE;

		if (streq(version, release))
		{
			found = TRUE;
			found_char = '*';
		}
		else if (security)
		{
			 snprintf(command, BUF_LEN, "dpkg --compare-versions %s lt %s",
										 release, version);
			if (system(command) == 0)
			{
				found_char = '!';
				if (!sec_flag)
				{
					if (db->execute(db, NULL, "UPDATE versions "
						"SET security = 1 WHERE id = ?", DB_INT, vid) != 1)
					{
						DBG1(DBG_IMV, "  could not update version");
						e->destroy(e);
						return FALSE;
					}
					update_version = TRUE;
					stats->updated_versions++;
				}
			}
		}
		if (debug_level < 2 && !update_version)
		{
			continue;
		}
		if (first)
		{
			DBG1(DBG_IMV, "%s", package);
			first = FALSE;
		}
		DBG1(DBG_IMV, "  %c%s %s", found_char , sec_flag ? "s" : " ", release);
	}
	e->destroy(e);

	if (!found)
	{
		if (first)
		{
			DBG1(DBG_IMV, "%s", package);
		}
		DBG1(DBG_IMV, "  +  %s", version);

		if (db->execute(db, &vid,
			"INSERT INTO versions "
			"(package, product, release, security, time) "
			"VALUES (?, ?, ?, 0, ?)", DB_INT, pid, DB_INT, stats->product,
			DB_TEXT, version, DB_INT, stats->release) != 1)
		{
			DBG1(DBG_IMV, "  could not store version to database");
			return FALSE;
		}
		stats->new_versions++;
	}

	return TRUE;
}

/**
 * Process a package file and store updates in the database
 */
static void process_packages(char *filename, char *product, bool security)
{
	char *uri, line[BUF_LEN], *pos, *package = NULL, *version = NULL;
	sec_update_state_t state;
	enumerator_t *e;
	database_t *db;
	int pid;
	FILE *file;
	stats_t stats;
	bool success;

	/* initialize statistics */
	memset(&stats, 0x00, sizeof(stats_t));

	/* Set release date to current time */
	stats.release = time(NULL);

	/* opening package file */
	DBG1(DBG_IMV, "loading \"%s\"", filename);
	file = fopen(filename, "r");
	if (!file)
	{
		DBG1(DBG_IMV, "  could not open \"%s\"", filename);
		exit(EXIT_FAILURE);
	}

	/* connect package database */
	uri = lib->settings->get_str(lib->settings, "sec-updater.database", NULL);
	if (!uri)
	{
		DBG1(DBG_IMV, "database URI sec-updater.database not set");
		fclose(file);
		exit(EXIT_FAILURE);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		DBG1(DBG_IMV, "could not connect to database '%s'", uri);
		fclose(file);
		exit(EXIT_FAILURE);
	}

	/* check if product is already in database */
	e = db->query(db, "SELECT id FROM products WHERE name = ?",
				  DB_TEXT, product, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &pid))
		{
			stats.product = pid;
		}
		e->destroy(e);
	}
	if (!stats.product)
	{
		if (db->execute(db, &pid, "INSERT INTO products (name) VALUES (?)",
						DB_TEXT, product) != 1)
		{
			DBG1(DBG_IMV, "could not store product '%s' to database",
							 product);
			fclose(file);
			db->destroy(db);
			exit(EXIT_FAILURE);
		}
		stats.product = pid;
	}

	state = SEC_UPDATE_STATE_BEGIN_PACKAGE;

	while (fgets(line, sizeof(line), file))
	{
		/* set read pointer to beginning of line */
		pos = line;

		switch (state)
		{
			case SEC_UPDATE_STATE_BEGIN_PACKAGE:
				pos = strstr(pos, "Package: ");
				if (!pos)
				{
					continue;
				}
				pos += 9;
				package = pos;
				pos = strchr(pos, '\n');
				if (pos)
				{
					package = strndup(package, pos - package);
					state = SEC_UPDATE_STATE_VERSION;
				}
				break;
			case SEC_UPDATE_STATE_VERSION:
				pos = strstr(pos, "Version: ");
				if (!pos)
				{
					continue;
				}
				pos += 9;
				version = pos;
				pos = strchr(pos, '\n');
				if (pos)
				{
					version = strndup(version, pos - version);
					state = SEC_UPDATE_STATE_END_PACKAGE;
				}
				break;
			case SEC_UPDATE_STATE_END_PACKAGE:
				if (*pos != '\n')
				{
					continue;
				}
				success = update_database(db, package, version, security, &stats);
				free(package);
				free(version);
				if (!success)
				{
					fclose(file);
					db->destroy(db);
					exit(EXIT_FAILURE);
				}
				state = SEC_UPDATE_STATE_BEGIN_PACKAGE;
		}
	}
	switch (state)
	{
		case SEC_UPDATE_STATE_END_PACKAGE:
			free(version);
			/* fall-through */
		case SEC_UPDATE_STATE_VERSION:
			free(package);
			break;
		default:
			break;
	}
	fclose(file);
	db->destroy(db);

	DBG1(DBG_IMV, "processed \"%s\": %d packages, %d new versions, "
				  "%d updated versions", filename, stats.packages,
				   stats.new_versions, stats.updated_versions);
}

static void do_args(int argc, char *argv[])
{
	char *filename = NULL, *product = NULL;
	bool security = FALSE;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "debug", required_argument, NULL, 'd' },
			{ "file", required_argument, NULL, 'f' },
			{ "product", required_argument, NULL, 'p' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "security", no_argument, NULL, 's' },
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
			case 'd':
				debug_level = atoi(optarg);
				continue;
			case 'f':
				filename = optarg;
				continue;
			case 'p':
				product = optarg;
				continue;
			case 'q':
				stderr_quiet = TRUE;
				continue;
			case 's':
				security = TRUE;
				continue;
		}
		break;
	}

	if (filename && product)
	{
		process_packages(filename, product, security);
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
	dbg = sec_updater_dbg;
	openlog("sec-updater", 0, LOG_DEBUG);

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL, "sec-updater"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "sec-updater.load", "sqlite")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	do_args(argc, argv);

	exit(EXIT_SUCCESS);
}

