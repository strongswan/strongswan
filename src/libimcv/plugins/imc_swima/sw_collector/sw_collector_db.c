/*
 * Copyright (C) 2017 Andreas Steffen
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

#include "sw_collector_db.h"

#include "swima/swima_event.h"

typedef struct private_sw_collector_db_t private_sw_collector_db_t;

/**
 * Private data of an sw_collector_db_t object.
 */
struct private_sw_collector_db_t {

	/**
	 * Public members of sw_collector_db_state_t
	 */
	sw_collector_db_t public;

	/**
	 * Epoch
	 */
	uint32_t epoch;

	/**
	 * Event ID of last event stored in database
	 */
	uint32_t last_eid;

	/**
	 * Software collector database
	 */
	database_t *db;

};

METHOD(sw_collector_db_t, add_event, uint32_t,
	private_sw_collector_db_t *this, char *timestamp)
{
	uint32_t eid = 0;

	if (this->db->execute(this->db, &eid,
			"INSERT INTO events (epoch, timestamp) VALUES (?, ?)",
			 DB_UINT, this->epoch, DB_TEXT, timestamp) != 1)
	{
		DBG1(DBG_IMC, "unable to insert event into database");
		return 0;
	}

	return eid;
}

METHOD(sw_collector_db_t, get_last_event, bool,
	private_sw_collector_db_t *this, uint32_t *eid, uint32_t *epoch,
	char **last_time)
{
	char *timestamp;
	enumerator_t *e;

	e = this->db->query(this->db,
			"SELECT id, epoch, timestamp FROM events ORDER BY timestamp DESC",
			DB_UINT, DB_UINT, DB_TEXT);
	if (!e)
	{
		DBG1(DBG_IMC, "database query for event failed");
		return FALSE;
	}
	if (e->enumerate(e, eid, epoch, &timestamp))
	{
		if (last_time)
		{
			*last_time = strdup(timestamp);
		}
	}
	else
	{
		*eid = 0;
	}
	e->destroy(e);

	return TRUE;
}

METHOD(sw_collector_db_t, add_sw_event, bool,
	private_sw_collector_db_t *this, uint32_t eid, uint32_t sw_id,
	uint8_t action)
{
	if (this->db->execute(this->db, NULL,
			"INSERT INTO sw_events (eid, sw_id, action) VALUES (?, ?, ?)",
			 DB_UINT, eid, DB_UINT, sw_id, DB_UINT, action) != 1)
	{
		DBG1(DBG_IMC, "unable to insert sw_event into database");
		return FALSE;
	}

	return TRUE;
}

METHOD(sw_collector_db_t, get_sw_id, uint32_t,
	private_sw_collector_db_t *this, char *package, char *version, char *name,
	uint8_t source, bool installed, bool check)
{
	uint32_t sw_id = 0, status;
	enumerator_t *e;

	/* Does software identifier already exist in database? */
	e = this->db->query(this->db,
			"SELECT id, installed FROM sw_identifiers WHERE name = ?",
			DB_TEXT, name, DB_UINT, DB_UINT);
	if (!e)
	{
		DBG1(DBG_IMC, "database query for sw_identifier failed");
		return 0;
	}
	if (!e->enumerate(e, &sw_id, &status))
	{
		sw_id = 0;
	}
	e->destroy(e);

	if (sw_id)
	{
		if (status == installed)
		{
			if (!check)
			{
				DBG1(DBG_IMC, "  Warning: sw_id %u is already %s", sw_id,
					 status ? "installed" : "deleted");
			}
			return sw_id;
		}
		if (check)
		{
			DBG1(DBG_IMC, "  Warning: sw_id %u is %s", sw_id,
				 status ? "installed" : "deleted");
		}

		/* Change installation status */
		if (this->db->execute(this->db, NULL,
				"UPDATE sw_identifiers SET installed = ? WHERE id = ?",
				 DB_UINT, installed, DB_UINT, sw_id) != 1)
		{
			DBG1(DBG_IMC, "unable to update sw_id status in database");
			return 0;
		}
	}
	else
	{
		/* Create new software identifier */
		if (this->db->execute(this->db, &sw_id,
				"INSERT INTO sw_identifiers "
				"(name, package, version, source, installed) VALUES "
				"(?, ?, ?, ?, ?)",
				 DB_TEXT, name, DB_TEXT, package, DB_TEXT, version,
				 DB_UINT, source, DB_UINT, installed) != 1)
		{
			DBG1(DBG_IMC, "unable to insert sw_id into database");
			return 0;
		}

		if (check || !installed)
		{
			add_sw_event(this, 1, sw_id, SWIMA_EVENT_ACTION_CREATION);
		}
	}

	return sw_id;
}

METHOD(sw_collector_db_t, get_sw_id_count, uint32_t,
	private_sw_collector_db_t *this, bool installed_only)
{
	uint32_t count;
	enumerator_t *e;

	if (installed_only)
	{
		e = this->db->query(this->db,
			"SELECT COUNT(installed) FROM sw_identifiers WHERE installed = 1 ",
			 DB_UINT);
	}
	else
	{
		e = this->db->query(this->db,
			"SELECT COUNT(installed) FROM sw_identifiers", DB_UINT);
	}

	if (!e)
	{
		DBG1(DBG_IMC, "database query for sw_identifier count failed");
		return 0;
	}
	if (!e->enumerate(e, &count))
	{
		count = 0;
	}
	e->destroy(e);

	return count;
}

METHOD(sw_collector_db_t, create_sw_enumerator, enumerator_t*,
	private_sw_collector_db_t *this, bool installed_only)
{
	enumerator_t *e;

	if (installed_only)
	{
		e = this->db->query(this->db,
				"SELECT name, package, version, installed FROM sw_identifiers "
				"WHERE installed = 1 ORDER BY name ASC",
				 DB_TEXT, DB_TEXT, DB_TEXT, DB_UINT);
	}
	else
	{
		e = this->db->query(this->db,
				"SELECT name, package, version, installed FROM sw_identifiers "
				"ORDER BY name ASC", DB_TEXT, DB_TEXT, DB_TEXT, DB_UINT);
	}
	if (!e)
	{
		DBG1(DBG_IMC, "database query for sw_identifier count failed");
		return NULL;
	}

	return e;
}

METHOD(sw_collector_db_t, destroy, void,
	private_sw_collector_db_t *this)
{
	this->db->destroy(this->db);
	free(this);
}

/**
 * Described in header.
 */
sw_collector_db_t *sw_collector_db_create(char *uri)
{
	private_sw_collector_db_t *this;
	uint32_t first_eid, last_eid;
	char *first_time;

	INIT(this,
		.public = {
			.add_event = _add_event,
			.get_last_event = _get_last_event,
			.add_sw_event = _add_sw_event,
			.get_sw_id = _get_sw_id,
			.get_sw_id_count = _get_sw_id_count,
			.create_sw_enumerator = _create_sw_enumerator,
			.destroy = _destroy,
		},
		.db = lib->db->create(lib->db, uri),
	);

	if (!this->db)
	{
		DBG1(DBG_IMC, "opening database URI '%s' failed", uri);
		return NULL;
	}

	/* Retrieve last event in database */
	if (!get_last_event(this, &last_eid, &this->epoch, NULL))
	{
		destroy(this);
		return NULL;
	}

	/* Create random epoch and first event if no events exist yet */
	if (!last_eid)
	{
		rng_t *rng;

		rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
		if (!rng ||
			!rng->get_bytes(rng, sizeof(uint32_t), (uint8_t*)&this->epoch))
		{
			DESTROY_IF(rng);
			destroy(this);
			DBG1(DBG_IMC, "generating random epoch value failed");
			return NULL;
		}
		rng->destroy(rng);

		/* Create first event when the OS was installed */
		first_time = lib->settings->get_str(lib->settings,
						"sw-collector.first_time", "0000-00-00T00:00:00Z");
		first_eid = add_event(this, first_time);
		if (!first_eid)
		{
			destroy(this);
			return NULL;
		}
		DBG0(DBG_IMC, "First-Date: %s, eid = %u, epoch = %u",
					   first_time, first_eid, this->epoch);
	}

	return &this->public;
}
