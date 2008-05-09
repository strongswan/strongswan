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
 *
 * $Id$
 */

#include "sql_attribute.h"

#include <daemon.h>
#include <utils/mutex.h>

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
	 * mutex to simulate transactions
	 */
	mutex_t *mutex;
};

/** 
 * convert a address blob to an ip of the correct family
 */
static host_t *ip_from_chunk(chunk_t address)
{
	switch (address.len)
	{
		case 4:
			return host_create_from_chunk(AF_INET, address, 0);
		case 16:
			return host_create_from_chunk(AF_INET6, address, 0);
		default:
			return NULL;
	}		
}

/**
 * increment a chunk, as it would reprensent a network order integer
 */
static void increment_chunk(chunk_t chunk)
{
	int i;
	
	for (i = chunk.len - 1; i >= 0; i++)
	{
		if (++chunk.ptr[i] != 0)
		{
			return;
		}
	}
}

/**
 * Lookup if we have an existing lease
 */
static host_t* get_lease(private_sql_attribute_t *this,
						 char *name, identification_t *id)
{
	enumerator_t *e;
	chunk_t address;
	host_t *ip = NULL;
	int lease;
	
	/* transaction simulation, see create_lease() */
	this->mutex->lock(this->mutex);
	
	/* select a lease for "id" which still valid */
	e = this->db->query(this->db,
						"SELECT l.id, l.address FROM leases AS l "
						"JOIN pools AS p ON l.pool = p.id "
						"JOIN identities AS i ON l.identity = i.id "
						"WHERE p.name = ? AND i.type = ? AND i.data = ? "
						"AND (l.release ISNULL OR p.timeout ISNULL "
						" OR (l.release >= (? - p.timeout))) "
						"ORDER BY l.acquire LIMIT 1", DB_TEXT, name,
						DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
						DB_UINT, time(NULL),
						DB_INT, DB_BLOB);
	if (e)
	{
		if (e->enumerate(e, &lease, &address))
		{
			/* found one, set the lease to active */
			if (this->db->execute(this->db, NULL,
						  "UPDATE leases SET release = NULL WHERE id = ?",
						  DB_INT, lease) > 0)
			{
				ip = ip_from_chunk(address);
				DBG1(DBG_CFG, "reassigning address from valid lease "
					 "from pool %s", name);
			}
		}
		e->destroy(e);
	}
	this->mutex->unlock(this->mutex);
	return ip;
}

/**
 * Create a new lease entry for client
 */
static host_t* create_lease(private_sql_attribute_t *this,
							char *name, identification_t *id)
{
	enumerator_t *e;
	chunk_t address;
	host_t *ip = NULL;
	int pool, identity = 0;
	bool new = FALSE;
	
	/* we currently do not use database transactions. While this would be 
	 * the clean way, there is no real advantage, but some disadvantages:
	 * - we would require InnoDB for mysql, as MyISAM does not support trans.
	 * - the mysql plugin uses connection pooling, and we would need a 
	 *   mechanism to lock transactions to a single connection.
	 */
	this->mutex->lock(this->mutex);
	
	/* find an address which has outdated leases only */
	e = this->db->query(this->db,
						"SELECT pool, address FROM leases "
						"JOIN pools ON leases.pool = pools.id "
						"WHERE name = ? "
						"GROUP BY address HAVING release NOTNULL "
						"AND MAX(release) < ? + pools.timeout LIMIT 1",
						DB_TEXT, name, DB_UINT, time(NULL),
						DB_INT, DB_BLOB);
	
	if (!e || !e->enumerate(e, &pool, &address))
	{
		DESTROY_IF(e);
		/* no outdated lease found, acquire new address */
		e = this->db->query(this->db,
				"SELECT id, next FROM pools WHERE name = ? AND next <= end",
				DB_TEXT, name,
				DB_INT, DB_BLOB);
		if (!e || !e->enumerate(e, &pool, &address))
		{
			/* pool seems full */
			DESTROY_IF(e);
			this->mutex->unlock(this->mutex);
			return NULL;
		}
		new = TRUE;
	}
	address = chunk_clonea(address);
	e->destroy(e);
	
	/* look for peer identity in the identities table */
	e = this->db->query(this->db,
						"SELECT id FROM identities WHERE type = ? AND data = ?",
						DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
						DB_INT);
	if (!e || !e->enumerate(e, &identity))
	{
		DESTROY_IF(e);
		/* not found, insert new one */
		this->db->execute(this->db, &identity,
					  "INSERT INTO identities (type, data) VALUES (?, ?)",
					  DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id));
	}
	else
	{
		e->destroy(e);
	}
	/* if we have an identity, insert a new lease */
	if (identity)
	{
		if (this->db->execute(this->db, NULL,
				 "INSERT INTO leases (pool, address, identity, acquire) "
				 "VALUES (?, ?, ?, ?)",
				 DB_INT, pool, DB_BLOB, address, DB_INT, identity,
				 DB_UINT, time(NULL)) > 0)
		{
			ip = ip_from_chunk(address);
			if (new)
			{	/* update next address, as we have consumed one */
				increment_chunk(address);
				this->db->execute(this->db, NULL,
								  "UPDATE pools set next = ? WHERE id = ?",
								  DB_BLOB, address, DB_INT, pool);
				DBG1(DBG_CFG, "assigning lease with new address "
					 "from pool %s", name);
			}
			else
			{
				DBG1(DBG_CFG, "reassigning address from expired lease "
					 "from pool %s", name);
			}
		}
	}
	this->mutex->unlock(this->mutex);
	return ip;
}

/**
 * Implementation of attribute_provider_t.acquire_address
 */
static host_t* acquire_address(private_sql_attribute_t *this,
							   char *name, identification_t *id,
							   auth_info_t *auth, host_t *requested)
{
	host_t *ip;
	
	ip = get_lease(this, name, id);
	if (!ip)
	{
		ip = create_lease(this, name, id);
	}
	return ip;
}

/**
 * Implementation of attribute_provider_t.release_address
 */
static bool release_address(private_sql_attribute_t *this,
							char *name, host_t *address)
{
	if (this->db->execute(this->db, NULL,
			"UPDATE leases SET release = ? WHERE "
			"pool IN (SELECT id FROM pools WHERE name = ?) AND "
			"address = ? AND release ISNULL",
			DB_UINT, time(NULL),
			DB_TEXT, name, DB_BLOB, address->get_address(address)) > 0)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of sql_attribute_t.destroy
 */
static void destroy(private_sql_attribute_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
sql_attribute_t *sql_attribute_create(database_t *db)
{
	private_sql_attribute_t *this = malloc_thing(private_sql_attribute_t);
	
	this->public.provider.acquire_address = (host_t*(*)(attribute_provider_t *this, char*, identification_t *,auth_info_t *, host_t *))acquire_address;
	this->public.provider.release_address = (bool(*)(attribute_provider_t *this, char*,host_t *))release_address;
	this->public.destroy = (void(*)(sql_attribute_t*))destroy;
	
	this->db = db;
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	return &this->public;
}

