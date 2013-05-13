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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "imv_database.h"
#include "imv_workitem.h"

#include <utils/debug.h>

typedef struct private_imv_database_t private_imv_database_t;

#define SESSION_TIME_DELTA_MAX		2  /* seconds */

#define DEFAULT_POLICY_SCRIPT		"ipsec _imv_policy"

/**
 * Private data of a imv_database_t object.
 *
 */
struct private_imv_database_t {

	/**
	 * Public imv_database_t interface.
	 */
	imv_database_t public;

	/**
	 * database instance
	 */
	database_t *db;

	/**
	 * policy script
	 */
	char *script;

};

METHOD(imv_database_t, get_session_id, int,
	private_imv_database_t *this, TNC_ConnectionID id, u_int32_t ar_id_type,
	chunk_t ar_id_value)
{
	enumerator_t *e;
	int ar_id = 0, session_id = 0;
	u_int created;
	time_t now;

	/* get most recent session for a given connection ID if available */
	e = this->db->query(this->db,
			"SELECT id, time FROM sessions WHERE connection = ? "
			"ORDER BY time DESC", DB_INT, id, DB_INT, DB_UINT);
	if (e)
	{
		e->enumerate(e, &session_id, &created);
		e->destroy(e);
	}

	/* get current time */
	now = time(NULL);

	/* check if a new session has already been created by another IMV */
	if (session_id && (now - created) <= SESSION_TIME_DELTA_MAX)
	{
		return session_id;
	}

	if (ar_id_value.len)
	{
		/* get primary key of AR identity if it exists */
		e = this->db->query(this->db,
				"SELECT id FROM identities WHERE type = ? AND value = ?",
				DB_INT, ar_id_type, DB_BLOB, ar_id_value, DB_INT);
		if (e)
		{
			e->enumerate(e, &ar_id);
			e->destroy(e);
		}

		/* if AR identity has not been found - register it */
		if (!ar_id)
		{
			this->db->execute(this->db, &ar_id,
				"INSERT INTO identities (type, value) VALUES (?, ?)",
				 DB_INT, ar_id_type, DB_BLOB, ar_id_value);
		}
	}

	/* create a new session ID */
	this->db->execute(this->db, &session_id,
			"INSERT INTO sessions (time, connection, identity) "
			"VALUES (?, ?, ?)", DB_UINT, now, DB_INT, id, DB_INT, ar_id);

	return session_id;
}

METHOD(imv_database_t, add_product, int,
	private_imv_database_t *this, int session_id, char *product)
{
	enumerator_t *e;
	int pid = 0;

	/* get primary key of product info string if it exists */
	e = this->db->query(this->db,
			"SELECT id FROM products WHERE name = ?", DB_TEXT, product, DB_INT);
	if (e)
	{
		e->enumerate(e, &pid);
		e->destroy(e);
	}

	/* if product info string has not been found - register it */
	if (!pid)
	{
		this->db->execute(this->db, &pid,
			"INSERT INTO products (name) VALUES (?)", DB_TEXT, product);
	}
	
	/* add product reference to session */
	if (pid)
	{
		this->db->execute(this->db, NULL,
			"UPDATE sessions SET product = ? WHERE id = ?",
			 DB_INT, pid, DB_INT, session_id);
	}

	return pid;
}

METHOD(imv_database_t, add_device, int,
	private_imv_database_t *this, int session_id, chunk_t device)
{
	enumerator_t *e;
	int did = 0;

	/* get primary key of device identification if it exists */
	e = this->db->query(this->db,
			"SELECT id FROM devices WHERE value = ?", DB_BLOB, device, DB_INT);
	if (e)
	{
		e->enumerate(e, &did);
		e->destroy(e);
	}

	/* if device identification has not been found - register it */
	if (!did)
	{
		this->db->execute(this->db, &did,
			"INSERT INTO devices (value) VALUES (?)", DB_BLOB, device);
	}
	
	/* add device reference to session */
	if (did)
	{
		this->db->execute(this->db, NULL,
			"UPDATE sessions SET device = ? WHERE id = ?",
			 DB_INT, did, DB_INT, session_id);
	}

	return did;
}

METHOD(imv_database_t, policy_script, bool,
	private_imv_database_t *this, int session_id, bool start)
{
	char command[512], resp[128], *last;
	FILE *shell;

	snprintf(command, sizeof(command), "2>&1 TNC_SESSION_ID='%d' %s %s",
			 session_id, this->script, start ? "start" : "stop");
	DBG3(DBG_IMV, "running policy script: %s", command);

	shell = popen(command, "r");
	if (shell == NULL)
	{
		DBG1(DBG_IMV, "could not execute policy script '%s'",
			 this->script);
		return FALSE;
	}
	while (TRUE)
	{
		if (fgets(resp, sizeof(resp), shell) == NULL)
		{
			if (ferror(shell))
			{
				DBG1(DBG_IMV, "error reading output from policy script");
			}
			break;
		}
		else
		{
			last = resp + strlen(resp) - 1;
			if (last >= resp && *last == '\n')
			{
				/* replace trailing '\n' */
				*last = '\0';
			}
			DBG1(DBG_IMV, "policy: %s", resp);
		}
	}
	pclose(shell);

	return TRUE;
}

typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** session ID */
	int session_id;
	/** database enumerator */
	enumerator_t *e;
} workitem_enumerator_t;

/**
 * Implementation of enumerator.enumerate
 */
static bool workitem_enumerator_enumerate(workitem_enumerator_t *this, ...)
{
	imv_workitem_t **workitem;
	imv_workitem_type_t type;
	int rec_fail, rec_noresult;
	char *argument;
	va_list args;

	va_start(args, this);
	workitem = va_arg(args, imv_workitem_t**);
	va_end(args);

	if (this->e->enumerate(this->e, &type, &argument, &rec_fail, &rec_noresult))
	{
		*workitem = imv_workitem_create(this->session_id, type, argument,
										rec_fail, rec_noresult);
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of enumerator.destroy
 */
static void workitem_enumerator_destroy(workitem_enumerator_t *this)
{
	this->e->destroy(this->e);
	free(this);
}

METHOD(imv_database_t, create_workitem_enumerator, enumerator_t*,
	private_imv_database_t *this, int session_id)
{
	workitem_enumerator_t *enumerator;
	enumerator_t *e;

	e = this->db->query(this->db,
				"SELECT type, argument, rec_fail, rec_noresult "
				"FROM workitems WHERE session = ?",
				DB_INT, session_id, DB_INT, DB_TEXT, DB_INT, DB_INT);
	if (!e)
	{
		return NULL;
	}

	INIT(enumerator,
		.public = {
			.enumerate = (void*)workitem_enumerator_enumerate,
			.destroy = (void*)workitem_enumerator_destroy,
		},
		.e = e,
	);

	return (enumerator_t*)enumerator;
}

METHOD(imv_database_t, get_database, database_t*,
	private_imv_database_t *this)
{
	return this->db;
}

METHOD(imv_database_t, destroy, void,
	private_imv_database_t *this)
{
	this->db->destroy(this->db);
	free(this);
}

/**
 * See header
 */
imv_database_t *imv_database_create(char *uri)
{
	private_imv_database_t *this;

	INIT(this,
		.public = {
			.get_session_id = _get_session_id,
			.add_product = _add_product,
			.add_device = _add_device,
			.policy_script = _policy_script,
			.create_workitem_enumerator = _create_workitem_enumerator,
			.get_database = _get_database,
			.destroy = _destroy,
		},
		.db = lib->db->create(lib->db, uri),
		.script = lib->settings->get_str(lib->settings,
					"libimcv.policy_script", DEFAULT_POLICY_SCRIPT),
	);

	if (!this->db)
	{
		DBG1(DBG_IMV,
			 "failed to connect to IMV database '%s'", uri);
		free(this);
		return NULL;
	}

	return &this->public;
}

