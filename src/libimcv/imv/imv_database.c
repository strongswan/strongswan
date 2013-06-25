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

#include <utils/debug.h>
#include <threading/mutex.h>

typedef struct private_imv_database_t private_imv_database_t;

/**
 * Private data of a imv_database_t object.
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

	/**
	 * Session list
	 */
	linked_list_t *sessions;

	/**
	 * mutex used to lock session list
	 */
	mutex_t *mutex;

};

METHOD(imv_database_t, add_session, imv_session_t*,
	private_imv_database_t *this, TNC_ConnectionID conn_id,
	u_int32_t ar_id_type, chunk_t ar_id_value)
{
	enumerator_t *enumerator, *e;
	imv_session_t *current, *session = NULL;
	int ar_id = 0, session_id;
	u_int created;

	this->mutex->lock(this->mutex);

	/* check if a session has already been assigned */
	enumerator = this->sessions->create_enumerator(this->sessions);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (conn_id == current->get_connection_id(current))
		{
			session = current;
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* session already exists */
	if (session)
	{
		this->mutex->unlock(this->mutex);
		return session->get_ref(session);
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
	/* create a new session entry */
	created = time(NULL);
	this->db->execute(this->db, &session_id,
				"INSERT INTO sessions (time, connection, identity) "
				"VALUES (?, ?, ?)",
				DB_UINT, created, DB_INT, conn_id, DB_INT, ar_id);
	session = imv_session_create(session_id, conn_id);
	this->sessions->insert_last(this->sessions, session);

	this->mutex->unlock(this->mutex);

	return session;
}

METHOD(imv_database_t, remove_session, void,
	private_imv_database_t *this, imv_session_t *session)
{
	enumerator_t *enumerator;
	imv_session_t *current;

	this->mutex->lock(this->mutex);
	enumerator = this->sessions->create_enumerator(this->sessions);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current == session)
		{
			this->sessions->remove_at(this->sessions, enumerator);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(imv_database_t, add_product, int,
	private_imv_database_t *this, imv_session_t *session, char *product)
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
			 DB_INT, pid, DB_INT, session->get_session_id(session));
	}

	return pid;
}

METHOD(imv_database_t, add_device, int,
	private_imv_database_t *this, imv_session_t *session, chunk_t device)
{
	enumerator_t *e;
	char *device_str;
	int pid = 0, did = 0;

	/* get primary key of product from session */
	e = this->db->query(this->db,
			"SELECT product FROM sessions WHERE id = ?",
			 DB_INT, session->get_session_id(session), DB_INT);
	if (e)
	{
		e->enumerate(e, &pid);
		e->destroy(e);
	}

	/* some IMV policy manager expect a text string */
	device_str = strndup(device.ptr, device.len);

	/* get primary key of device identification if it exists */
	e = this->db->query(this->db,
			"SELECT id FROM devices WHERE value = ? AND product = ?",
			 DB_TEXT, device_str, DB_INT, pid, DB_INT);
	if (e)
	{
		e->enumerate(e, &did);
		e->destroy(e);
	}

	/* if device identification has not been found - register it */
	if (!did)
	{
		this->db->execute(this->db, &did,
			"INSERT INTO devices (value, product) VALUES (?, ?)",
			 DB_TEXT, device_str, DB_INT, pid);
	}
	free(device_str);
	
	/* add device reference to session */
	if (did)
	{
		this->db->execute(this->db, NULL,
			"UPDATE sessions SET device = ? WHERE id = ?",
			 DB_INT, did, DB_INT, session->get_session_id(session));
	}

	return did;
}

METHOD(imv_database_t, add_recommendation, void,
	private_imv_database_t *this, imv_session_t *session,
	TNC_IMV_Action_Recommendation rec)
{
	/* add final recommendation to session */
	this->db->execute(this->db, NULL,
			"UPDATE sessions SET rec = ? WHERE id = ?",
			 DB_INT, rec, DB_INT, session->get_session_id(session));
}

METHOD(imv_database_t, policy_script, bool,
	private_imv_database_t *this, imv_session_t *session, bool start)
{
	imv_workitem_t *workitem;
	imv_workitem_type_t type;
	int id, session_id, arg_int, rec_fail, rec_noresult;
	enumerator_t *e;
	char command[512], resp[128], *last, *arg_str;
	FILE *shell;

	session_id = session->get_session_id(session);

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

	if (start && !session->get_policy_started(session))
	{
		/* get workitem list generated by policy manager */
		e = this->db->query(this->db,
				"SELECT id, type, arg_str, arg_int, rec_fail, rec_noresult "
				"FROM workitems WHERE session = ?",	DB_INT, session_id,
				 DB_INT, DB_INT, DB_TEXT, DB_INT,DB_INT, DB_INT);
		if (!e)
		{
			DBG1(DBG_IMV, "no workitem enumerator returned");
			return FALSE;
		}
		while (e->enumerate(e, &id, &type, &arg_str, &arg_int, &rec_fail,
							   &rec_noresult))
		{
			workitem = imv_workitem_create(id, type, arg_str, arg_int, rec_fail,
										   rec_noresult);
			session->insert_workitem(session, workitem);
		}
		e->destroy(e);

		session->set_policy_started(session, TRUE);
	}
	else if (!start && session->get_policy_started(session))
	{
		session->set_policy_started(session, FALSE);
	}

	return TRUE;
}

METHOD(imv_database_t, finalize_workitem, bool,
	private_imv_database_t *this, imv_workitem_t *workitem)
{
	char *result;
	int rec;

	rec = workitem->get_result(workitem, &result);

	return this->db->execute(this->db, NULL,
				"UPDATE workitems SET result = ?, rec_final = ? WHERE id = ?",
				DB_TEXT, result, DB_INT, rec,
				DB_INT, workitem->get_id(workitem)) == 1;
}

METHOD(imv_database_t, get_database, database_t*,
	private_imv_database_t *this)
{
	return this->db;
}

METHOD(imv_database_t, destroy, void,
	private_imv_database_t *this)
{
	DESTROY_IF(this->db);
	this->sessions->destroy_offset(this->sessions,
							offsetof(imv_session_t, destroy));
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
imv_database_t *imv_database_create(char *uri, char *script)
{
	private_imv_database_t *this;

	INIT(this,
		.public = {
			.add_session = _add_session,
			.remove_session = _remove_session,
			.add_product = _add_product,
			.add_device = _add_device,
			.add_recommendation = _add_recommendation,
			.policy_script = _policy_script,
			.finalize_workitem = _finalize_workitem,
			.get_database = _get_database,
			.destroy = _destroy,
		},
		.db = lib->db->create(lib->db, uri),
		.script = script,
		.sessions = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (!this->db)
	{
		DBG1(DBG_IMV,
			 "failed to connect to IMV database '%s'", uri);
		destroy(this);
		return NULL;
	}

	return &this->public;
}

