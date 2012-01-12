/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include <time.h>

#include <debug.h>
#include <library.h>

#include "sql_attribute.h"

typedef struct private_sql_attribute_t private_sql_attribute_t;

/**
 * private data of sql_attribute
 */
struct private_sql_attribute_t {

	/**
	 * public functions
	 */
	sql_attribute_t public;

	/**
	 * database connection
	 */
	database_t *db;

	/**
	 * whether to record lease history in lease table
	 */
	bool history;
};

/**
 * lookup/insert an identity
 */
static u_int get_identity(private_sql_attribute_t *this, identification_t *id)
{
	enumerator_t *e;
	u_int row;

	/* look for peer identity in the identities table */
	e = this->db->query(this->db,
						"SELECT id FROM identities WHERE type = ? AND data = ?",
						DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
						DB_UINT);

	if (e && e->enumerate(e, &row))
	{
		e->destroy(e);
		return row;
	}
	DESTROY_IF(e);
	/* not found, insert new one */
	if (this->db->execute(this->db, &row,
				  "INSERT INTO identities (type, data) VALUES (?, ?)",
				  DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id)) == 1)
	{
		return row;
	}
	return 0;
}

/**
 * Lookup an attribute pool by name
 */
static u_int get_attr_pool(private_sql_attribute_t *this, char *name)
{
	enumerator_t *e;
	u_int row = 0;

	e = this->db->query(this->db,
						"SELECT id FROM attribute_pools WHERE name = ?",
						DB_TEXT, name, DB_UINT);
	if (e)
	{
		e->enumerate(e, &row);
	}
	DESTROY_IF(e);

	return row;
}

/**
 * Lookup pool by name
 */
static u_int get_pool(private_sql_attribute_t *this, char *name, u_int *timeout)
{
	enumerator_t *e;
	u_int pool;

	e = this->db->query(this->db, "SELECT id, timeout FROM pools WHERE name = ?",
						DB_TEXT, name, DB_UINT, DB_UINT);
	if (e && e->enumerate(e, &pool, timeout))
	{
		e->destroy(e);
		return pool;
	}
	DESTROY_IF(e);
	return 0;
}

/**
 * Look up an existing lease
 */
static host_t* check_lease(private_sql_attribute_t *this, char *name,
						   u_int pool, u_int identity)
{
	while (TRUE)
	{
		u_int id;
		chunk_t address;
		enumerator_t *e;
		time_t now = time(NULL);

		e = this->db->query(this->db,
				"SELECT id, address FROM addresses "
				"WHERE pool = ? AND identity = ? AND released != 0 LIMIT 1",
				DB_UINT, pool, DB_UINT, identity, DB_UINT, DB_BLOB);
		if (!e || !e->enumerate(e, &id, &address))
		{
			DESTROY_IF(e);
			break;
		}
		address = chunk_clonea(address);
		e->destroy(e);

		if (this->db->execute(this->db, NULL,
				"UPDATE addresses SET acquired = ?, released = 0 "
				"WHERE id = ? AND identity = ? AND released != 0",
				DB_UINT, now, DB_UINT, id, DB_UINT, identity) > 0)
		{
			host_t *host;

			host = host_create_from_chunk(AF_UNSPEC, address, 0);
			if (host)
			{
				DBG1(DBG_CFG, "acquired existing lease for address %H in"
					 " pool '%s'", host, name);
				return host;
			}
		}
	}
	return NULL;
}

/**
 * We check for unallocated addresses or expired leases. First we select an
 * address as a candidate, but double check later on if it is still available
 * during the update operation. This allows us to work without locking.
 */
static host_t* get_lease(private_sql_attribute_t *this, char *name,
						 u_int pool, u_int timeout, u_int identity)
{
	while (TRUE)
	{
		u_int id;
		chunk_t address;
		enumerator_t *e;
		time_t now = time(NULL);
		int hits;

		if (timeout)
		{
			/* check for an expired lease */
			e = this->db->query(this->db,
				"SELECT id, address FROM addresses "
				"WHERE pool = ? AND released != 0 AND released < ? LIMIT 1",
				DB_UINT, pool, DB_UINT, now - timeout, DB_UINT, DB_BLOB);
		}
		else
		{
			/* with static leases, check for an unallocated address */
			e = this->db->query(this->db,
				"SELECT id, address FROM addresses "
				"WHERE pool = ? AND identity = 0 LIMIT 1",
				DB_UINT, pool, DB_UINT, DB_BLOB);

		}

		if (!e || !e->enumerate(e, &id, &address))
		{
			DESTROY_IF(e);
			break;
		}
		address = chunk_clonea(address);
		e->destroy(e);

		if (timeout)
		{
			hits = this->db->execute(this->db, NULL,
						"UPDATE addresses SET "
						"acquired = ?, released = 0, identity = ? "
						"WHERE id = ? AND released != 0 AND released < ?",
						DB_UINT, now, DB_UINT, identity,
						DB_UINT, id, DB_UINT, now - timeout);
		}
		else
		{
			hits = this->db->execute(this->db, NULL,
						"UPDATE addresses SET "
						"acquired = ?, released = 0, identity = ? "
						"WHERE id = ? AND identity = 0",
						DB_UINT, now, DB_UINT, identity, DB_UINT, id);
		}
		if (hits > 0)
		{
			host_t *host;

			host = host_create_from_chunk(AF_UNSPEC, address, 0);
			if (host)
			{
				DBG1(DBG_CFG, "acquired new lease for address %H in pool '%s'",
					 host, name);
				return host;
			}
		}
	}
	DBG1(DBG_CFG, "no available address found in pool '%s'", name);
	return NULL;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_sql_attribute_t *this, char *names, identification_t *id,
	host_t *requested)
{
	host_t *address = NULL;
	u_int identity, pool, timeout;

	identity = get_identity(this, id);
	if (identity)
	{
		/* check for a single pool first (no concatenation and enumeration) */
		if (strchr(names, ',') == NULL)
		{
			pool = get_pool(this, names, &timeout);
			if (pool)
			{
				/* check for an existing lease */
				address = check_lease(this, names, pool, identity);
				if (address == NULL)
				{
					/* get an unallocated address or expired lease */
					address = get_lease(this, names, pool, timeout, identity);
				}
			}
		}
		else
		{
			enumerator_t *enumerator;
			char *name;

			/* in a first step check for an existing lease over all pools */
			enumerator = enumerator_create_token(names, ",", " ");
			while (enumerator->enumerate(enumerator, &name))
			{
				pool = get_pool(this, name, &timeout);
				if (pool)
				{
					address = check_lease(this, name, pool, identity);
					if (address)
					{
						enumerator->destroy(enumerator);
						return address;
					}
				}
			}
			enumerator->destroy(enumerator);

			/* in a second step get an unallocated address or expired lease */
			enumerator = enumerator_create_token(names, ",", " ");
			while (enumerator->enumerate(enumerator, &name))
			{
				pool = get_pool(this, name, &timeout);
				if (pool)
				{
					address = get_lease(this, name, pool, timeout, identity);
					if (address)
					{
						break;
					}
				}
			}
			enumerator->destroy(enumerator);
		}
	}
	return address;
}

METHOD(attribute_provider_t, release_address, bool,
	private_sql_attribute_t *this, char *name, host_t *address,
	identification_t *id)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	time_t now = time(NULL);

	enumerator = enumerator_create_token(name, ",", " ");
	while (enumerator->enumerate(enumerator, &name))
	{
		u_int pool, timeout;

		pool = get_pool(this, name, &timeout);
		if (pool)
		{
			if (this->history)
			{
				this->db->execute(this->db, NULL,
					"INSERT INTO leases (address, identity, acquired, released)"
					" SELECT id, identity, acquired, ? FROM addresses "
					" WHERE pool = ? AND address = ?",
					DB_UINT, now, DB_UINT, pool,
					DB_BLOB, address->get_address(address));
			}
			if (this->db->execute(this->db, NULL,
					"UPDATE addresses SET released = ? WHERE "
					"pool = ? AND address = ?", DB_UINT, time(NULL),
					DB_UINT, pool, DB_BLOB, address->get_address(address)) > 0)
			{
				found = TRUE;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_sql_attribute_t *this, char *names, identification_t *id,
	host_t *vip)
{
	enumerator_t *attr_enumerator = NULL;

	if (vip)
	{
		enumerator_t *names_enumerator;
		u_int count;
		char *name;

		this->db->execute(this->db, NULL, "BEGIN EXCLUSIVE TRANSACTION");

		/* in a first step check for attributes that match name and id */
		if (id)
		{
			u_int identity = get_identity(this, id);

			names_enumerator = enumerator_create_token(names, ",", " ");
			while (names_enumerator->enumerate(names_enumerator, &name))
			{
				u_int attr_pool = get_attr_pool(this, name);
				if (!attr_pool)
				{
					continue;
				}

				attr_enumerator = this->db->query(this->db,
								"SELECT count(*) FROM attributes "
								"WHERE pool = ? AND identity = ?",
								DB_UINT, attr_pool, DB_UINT, identity, DB_UINT);

				if (attr_enumerator &&
					attr_enumerator->enumerate(attr_enumerator, &count) &&
					count != 0)
				{
					attr_enumerator->destroy(attr_enumerator);
					attr_enumerator = this->db->query(this->db,
								"SELECT type, value FROM attributes "
								"WHERE pool = ? AND identity = ?", DB_UINT,
								attr_pool, DB_UINT, identity, DB_INT, DB_BLOB);
					break;
				}
				DESTROY_IF(attr_enumerator);
				attr_enumerator = NULL;
			}
			names_enumerator->destroy(names_enumerator);
		}

		/* in a second step check for attributes that match name */
		if (!attr_enumerator)
		{
			names_enumerator = enumerator_create_token(names, ",", " ");
			while (names_enumerator->enumerate(names_enumerator, &name))
			{
				u_int attr_pool = get_attr_pool(this, name);
				if (!attr_pool)
				{
					continue;
				}

				attr_enumerator = this->db->query(this->db,
									"SELECT count(*) FROM attributes "
									"WHERE pool = ? AND identity = 0",
									DB_UINT, attr_pool, DB_UINT);

				if (attr_enumerator &&
					attr_enumerator->enumerate(attr_enumerator, &count) &&
					count != 0)
				{
					attr_enumerator->destroy(attr_enumerator);
					attr_enumerator = this->db->query(this->db,
									"SELECT type, value FROM attributes "
									"WHERE pool = ? AND identity = 0",
									DB_UINT, attr_pool, DB_INT, DB_BLOB);
					break;
				}
				DESTROY_IF(attr_enumerator);
				attr_enumerator = NULL;
			}
			names_enumerator->destroy(names_enumerator);
		}

		this->db->execute(this->db, NULL, "END TRANSACTION");

		/* lastly try to find global attributes */
		if (!attr_enumerator)
		{
			attr_enumerator = this->db->query(this->db,
									"SELECT type, value FROM attributes "
									"WHERE pool = 0 AND identity = 0",
									DB_INT, DB_BLOB);
		}
	}

	return (attr_enumerator ? attr_enumerator : enumerator_create_empty());
}

METHOD(sql_attribute_t, destroy, void,
	private_sql_attribute_t *this)
{
	free(this);
}

/*
 * see header file
 */
sql_attribute_t *sql_attribute_create(database_t *db)
{
	private_sql_attribute_t *this;
	time_t now = time(NULL);

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.db = db,
		.history = lib->settings->get_bool(lib->settings,
							"libhydra.plugins.attr-sql.lease_history", TRUE),
	);

	/* close any "online" leases in the case we crashed */
	if (this->history)
	{
		this->db->execute(this->db, NULL,
					"INSERT INTO leases (address, identity, acquired, released)"
					" SELECT id, identity, acquired, ? FROM addresses "
					" WHERE released = 0", DB_UINT, now);
	}
	this->db->execute(this->db, NULL,
					  "UPDATE addresses SET released = ? WHERE released = 0",
					  DB_UINT, now);
	return &this->public;
}

