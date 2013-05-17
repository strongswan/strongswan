/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "imv_policy_manager_usage.h"
#include "imv_workitem.h"
 
#include <library.h>
#include <utils/debug.h>

#include <stdlib.h>
#include <stdio.h>

/**
 * global debug output variables
 */
static int debug_level = 2;
static bool stderr_quiet = FALSE;

/**
 * attest dbg function
 */
static void stderr_dbg(debug_t group, level_t level, char *fmt, ...)
{
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
	}
}

bool policy_start(database_t *db, int session_id)
{
 	if (db->execute(db, NULL,
				"INSERT INTO workitems (session, type, argument, "
				"rec_fail, rec_noresult) VALUES (?, ?, ?, ?, ?)",
				DB_INT, session_id, DB_INT, IMV_WORKITEM_PACKAGES,
				DB_TEXT, "",
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS) != 1)
	{
		return FALSE;
	}
	if (db->execute(db, NULL,
				"INSERT INTO workitems (session, type, argument, "
				"rec_fail, rec_noresult) VALUES (?, ?, ?, ?, ?)",
				DB_INT, session_id, DB_INT, IMV_WORKITEM_FORWARDING,
				DB_TEXT, "",
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS) != 1)
	{
		return FALSE;
	}
	if (db->execute(db, NULL,
				"INSERT INTO workitems (session, type, argument, "
				"rec_fail, rec_noresult) VALUES (?, ?, ?, ?, ?)",
				DB_INT, session_id, DB_INT, IMV_WORKITEM_TCP_SCAN,
				DB_TEXT, "22",
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
				DB_INT, TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS) != 1)
	{
		return FALSE;
	}

	return TRUE;
}

bool policy_stop(database_t *db, int session_id)
{
	return db->execute(db, NULL,
				"DELETE FROM workitems WHERE session = ?",
				DB_UINT, session_id) > 0;
}

int main(int argc, char *argv[])
{
	database_t *db;
	char *uri, *tnc_session_id;
	int session_id;
	bool start, success;

	/* enable attest debugging hook */
	dbg = stderr_dbg;

	atexit(library_deinit);

	/* initialize library */
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, NULL, 
			lib->settings->get_str(lib->settings, "imv_policy_manager.load",
				 "sqlite")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	if (argc < 2)
	{
		usage();
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	if (streq(argv[1], "start"))
	{
		start = TRUE;
	}
	else if (streq(argv[1], "stop"))
	{
		start = FALSE;
	}
	else
	{
		usage();
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	/* get session ID */
	tnc_session_id = getenv("TNC_SESSION_ID");
	if (!tnc_session_id)
	{
		fprintf(stderr, "environment variable TNC_SESSION_ID is not defined\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	session_id = atoi(tnc_session_id);
	
	/* attach IMV database */
	uri = lib->settings->get_str(lib->settings, "libimcv.database", NULL);
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "opening database failed.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	if (start)
	{
		success = policy_start(db, session_id);
	}
	else
	{
		success = policy_stop(db, session_id);
	}
	db->destroy(db);

	fprintf(stderr, "imv_policy_manager %s %s\n", start ? "start" : "stop",
			success ? "successful" : "failed");

	exit(EXIT_SUCCESS);
}

