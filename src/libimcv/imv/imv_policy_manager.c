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
static int debug_level = 1;
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
	enumerator_t *e;
	int id, gid, device_id, product_id, group_id = 0;
	int type, file, dir, arg_int, rec_fail, rec_noresult;
	char *argument;

	/* get session data */
	e = db->query(db,
			"SELECT device, product FROM sessions WHERE id = ? ",
			 DB_INT, session_id, DB_INT, DB_INT);
	if (!e || !e->enumerate(e, &device_id, &product_id))
	{
		DESTROY_IF(e);
		fprintf(stderr, "session %d not found\n", session_id);
		return FALSE;
	}
	e->destroy(e);

	/* if a device ID exists, check if device belongs to a group */
	if (device_id)
	{
		e = db->query(db,
				"SELECT group_id FROM group_members WHERE device = ?",
				 DB_INT, device_id, DB_INT);
		if (e)
		{
			if (e->enumerate(e, &gid))
			{
				group_id = gid;
			}
			e->destroy(e);
		}
	}

	/* if no group membership found, try default product group */
	if (!group_id)
	{
		e = db->query(db,
				"SELECT group_id FROM default_product_groups WHERE product = ?",
				 DB_INT, product_id, DB_INT);
		if (e)
		{
			if (e->enumerate(e, &gid))
			{
				group_id = gid;
			}
			e->destroy(e);
		}
	}

	/* if still no group membership found, leave */
	if (!group_id)
	{
		fprintf(stderr, "no group membership found\n");
		return TRUE;
	}

	/* get enforcements for given group */
	e = db->query(db,
			"SELECT e.id, "
			"p.type, p.argument, p.file, p.dir, p.rec_fail, p.rec_noresult "
			"FROM enforcements AS e JOIN policies as p ON  e.policy = p.id "
			"WHERE e.group_id = ?", DB_INT, group_id,
			 DB_INT, DB_INT, DB_TEXT, DB_INT, DB_INT, DB_INT, DB_INT);
	if (!e)
	{
		return FALSE;
	}
	while (e->enumerate(e, &id, &type, &argument, &file, &dir, &rec_fail,
						   &rec_noresult))
	{
		/* determine arg_int */
		switch ((imv_workitem_type_t)type)
		{
			case IMV_WORKITEM_FILE_REF_MEAS:
			case IMV_WORKITEM_FILE_MEAS:
			case IMV_WORKITEM_FILE_META:
				arg_int = file;
				break;
			case IMV_WORKITEM_DIR_REF_MEAS:
			case IMV_WORKITEM_DIR_MEAS:
			case IMV_WORKITEM_DIR_META:
				arg_int = dir;
				break;
			default:
				arg_int = 0;
		}

		/* insert a workitem */
		if (db->execute(db, NULL,
				"INSERT INTO workitems (session, enforcement, type, arg_str, "
				"arg_int, rec_fail, rec_noresult) VALUES (?, ?, ?, ?, ?, ?, ?)",
				DB_INT, session_id, DB_INT, id, DB_INT, type, DB_TEXT, argument,
				DB_INT, arg_int, DB_INT, rec_fail, DB_INT, rec_noresult) != 1)
		{
			e->destroy(e);
			fprintf(stderr, "could not insert workitem\n");
			return FALSE;
		}
	}
	e->destroy(e);

	return TRUE;
}

bool policy_stop(database_t *db, int session_id)
{
	enumerator_t *e;
	int rec, policy;
	char *result;

	e = db->query(db,
			"SELECT w.rec_final, w.result, e.policy FROM workitems AS w "
			"JOIN enforcements AS e ON w.enforcement = e.id "
			"WHERE w.session = ? AND w.result IS NOT NULL",
			 DB_INT, session_id, DB_INT, DB_TEXT, DB_INT);
	if (e)
	{
		while (e->enumerate(e, &rec, &result, &policy))
		{
			db->execute(db, NULL,
				"INSERT INTO results (session, policy, rec, result) "
				"VALUES (?, ?, ?, ?)", DB_INT, session_id, DB_INT, policy,
				 DB_INT, rec, DB_TEXT, result);
		}
		e->destroy(e);
	}
	return db->execute(db, NULL,
				"DELETE FROM workitems WHERE session = ?",
				DB_UINT, session_id) >= 0;
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
	if (!uri)
	{
		fprintf(stderr, "database uri not defined.\n");
		exit(SS_RC_INITIALIZATION_FAILED);
	}

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

