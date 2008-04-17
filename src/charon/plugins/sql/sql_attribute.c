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
	
				POS;
	e = this->db->query(this->db,
						"SELECT l.id, l.address FROM leases AS l "
						"JOIN pools AS p ON l.pool = p.id "
						"JOIN identities AS i ON l.identity = i.id "
						"WHERE p.name = ? AND i.type = ? AND i.data = ? "
						"AND (l.release ISNULL OR p.timeout ISNULL "
						" OR (l.release < (p.timeout + l.acquire))) "
						"ORDER BY l.acquire LIMIT 1", DB_TEXT, name,
						DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
						DB_INT, DB_BLOB);
	if (e)
	{
		if (e->enumerate(e, &lease, &address))
		{
			if (this->db->execute(this->db, NULL,
						  "UPDATE leases SET release = NULL WHERE id = ?",
						  DB_INT, lease) > 0)
			{
				POS;
				ip = ip_from_chunk(address);
			}
		}
		e->destroy(e);
	}
	return ip;
}

/**
 * Create a new lease entry for client
 */
static host_t* create_lease(private_sql_attribute_t *this,
							char *name, identification_t *id)
{
	enumerator_t *e, *f;
	chunk_t address;
	host_t *ip = NULL;
	int pool, identity = 0;
				POS;
	
	e = this->db->query(this->db,
			"SELECT id, next FROM pools WHERE name = ? AND next <= end",
			DB_TEXT, name,
			DB_INT, DB_BLOB);
	if (!e)
	{
		return NULL;
	}
	if (e->enumerate(e, &pool, &address))
	{
		f = this->db->query(this->db,
						"SELECT id FROM identities WHERE type = ? AND data = ?",
						DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
						DB_INT);
		if (f)
		{
			if (!f->enumerate(f, &identity))
			{
				this->db->execute(this->db, &identity,
					  "INSERT INTO identities (type, data) VALUES (?, ?)",
					  DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id));
			}
			f->destroy(f);
		}
		if (identity)
		{
			if (this->db->execute(this->db, NULL,
						  "INSERT INTO leases "
						  "(pool, address, identity) VALUES (?, ?, ?)",
						  DB_INT, pool, DB_BLOB, address, DB_INT, identity) > 0)
			{
				POS;
				ip = ip_from_chunk(address);
				increment_chunk(address);
				this->db->execute(this->db, NULL,
								  "UPDATE pools set next = ? WHERE id = ?",
								  DB_BLOB, address, DB_INT, pool);
			}
		}
	}
	e->destroy(e);
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
			"UPDATE leases SET release = DATE('NOW') WHERE "
			"pool IN (SELECT id FROM pools WHERE name = ?) AND "
			"address = ? "
			"ORDER BY acquire LIMIT 1",
			DB_TEXT, name, DB_BLOB, address->get_address(address)) > 0)
	{
				POS;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of sql_attribute_t.destroy
 */
static void destroy(private_sql_attribute_t *this)
{
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
	
	return &this->public;
}

