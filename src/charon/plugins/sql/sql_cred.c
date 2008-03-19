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
 * $Id: sql_cred.c 3589 2008-03-13 14:14:44Z martin $
 */

#include <string.h>

#include "sql_cred.h"

#include <daemon.h>

typedef struct private_sql_cred_t private_sql_cred_t;

/**
 * Private data of an sql_cred_t object
 */
struct private_sql_cred_t {

	/**
	 * Public part
	 */
	sql_cred_t public;
	
	/**
	 * database connection
	 */
	database_t *db;
};

/**
 * enumerator over private keys
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** inner SQL enumerator */
	enumerator_t *inner;
	/** currently enumerated private key */
	private_key_t *current;
} private_enumerator_t;

/**
 * Implementation of private_enumerator_t.public.enumerate
 */
static bool private_enumerator_enumerate(private_enumerator_t *this,
										 private_key_t **key)
{
	chunk_t blob;
	int type;

	DESTROY_IF(this->current);
	while (this->inner->enumerate(this->inner, &type, &blob))
	{
		this->current = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
										   BUILD_BLOB_ASN1_DER, chunk_clone(blob),
										   BUILD_END);
		if (this->current)
		{
			*key = this->current;
			return TRUE;
		}
	}
	this->current = NULL;
	return FALSE;
}

/**
 * Implementation of private_enumerator_t.public.destroy
 */
static void private_enumerator_destroy(private_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of credential_set_t.create_private_enumerator.
 */
static enumerator_t* create_private_enumerator(private_sql_cred_t *this,
											   key_type_t type,
											   identification_t *id)
{
	private_enumerator_t *e;
	
	e = malloc_thing(private_enumerator_t);
	e->current = NULL;
	e->public.enumerate = (void*)private_enumerator_enumerate;
	e->public.destroy = (void*)private_enumerator_destroy;
	if (id && id->get_type(id) != ID_ANY)
	{
		e->inner = this->db->query(this->db,
				"SELECT p.type, p.data FROM private_keys AS p "
				"JOIN private_key_identity AS pi ON p.id = pi.private_key "
				"JOIN identities AS i ON pi.identity = i.id "
				"WHERE i.type = ? AND i.data = ? AND (? OR p.type = ?)",
				DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
				DB_INT, type == KEY_ANY, DB_INT, type,
				DB_INT, DB_BLOB);
	}
	else
	{
		e->inner = this->db->query(this->db,
				"SELECT type, data FROM private_keys WHERE (? OR type = ?)",
				DB_INT, type == KEY_ANY, DB_INT, type,
				DB_INT, DB_BLOB);
	}
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * enumerator over certificates
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** inner SQL enumerator */
	enumerator_t *inner;
	/** currently enumerated cert */
	certificate_t *current;
} cert_enumerator_t;

/**
 * Implementation of cert_enumerator_t.public.enumerate
 */
static bool cert_enumerator_enumerate(cert_enumerator_t *this,
									  certificate_t **cert)
{
	chunk_t blob;
	int type;

	DESTROY_IF(this->current);
	while (this->inner->enumerate(this->inner, &type, &blob))
	{
		this->current = lib->creds->create(lib->creds, CRED_CERTIFICATE, type,
										   BUILD_BLOB_ASN1_DER, chunk_clone(blob),
										   BUILD_END);
		if (this->current)
		{
			*cert = this->current;
			return TRUE;
		}
	}
	this->current = NULL;
	return FALSE;
}

/**
 * Implementation of cert_enumerator_t.public.destroy
 */
static void cert_enumerator_destroy(cert_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of credential_set_t.create_cert_enumerator.
 */
static enumerator_t* create_cert_enumerator(private_sql_cred_t *this,
										certificate_type_t cert, key_type_t key,
										identification_t *id, bool trusted)
{
	cert_enumerator_t *e;
	
	e = malloc_thing(cert_enumerator_t);
	e->current = NULL;
	e->public.enumerate = (void*)cert_enumerator_enumerate;
	e->public.destroy = (void*)cert_enumerator_destroy;
	if (id && id->get_type(id) != ID_ANY)
	{
		e->inner = this->db->query(this->db,
				"SELECT c.type, c.data FROM certificates AS c "
				"JOIN certificate_identity AS ci ON c.id = ci.certificate "
				"JOIN identities AS i ON ci.identity = i.id "
				"WHERE i.type = ? AND i.data = ? AND "
				"(? OR c.type = ?) AND (? OR c.keytype = ?)",
				DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
				DB_INT, cert == CERT_ANY, DB_INT, cert,
				DB_INT, key == KEY_ANY, DB_INT, key,
				DB_INT, DB_BLOB);
	}
	else
	{
		e->inner = this->db->query(this->db,
				"SELECT type, data FROM certificates WHERE "
				"(? OR type = ?) AND (? OR keytype = ?)",
				DB_INT, cert == CERT_ANY, DB_INT, cert,
				DB_INT, key == KEY_ANY, DB_INT, key,
				DB_INT, DB_BLOB);
	}
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * enumerator over shared keys
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** inner SQL enumerator */
	enumerator_t *inner;
	/** own identity */
	identification_t *me;
	/** remote identity */
	identification_t *other;
	/** currently enumerated private key */
	shared_key_t *current;
} shared_enumerator_t;

/**
 * Implementation of shared_enumerator_t.public.enumerate
 */
static bool shared_enumerator_enumerate(shared_enumerator_t *this,
										shared_key_t **shared,
										id_match_t *me, id_match_t *other)
{
	chunk_t blob;
	int type;

	DESTROY_IF(this->current);
	while (this->inner->enumerate(this->inner, &type, &blob))
	{
		this->current = shared_key_create(type, chunk_clone(blob));
		if (this->current)
		{
			*shared = this->current;
			if (me)
			{
				*me = this->me ? ID_MATCH_PERFECT : ID_MATCH_ANY;
			}
			if (other)
			{
				*other = this->other ? ID_MATCH_PERFECT : ID_MATCH_ANY;
			}
			return TRUE;
		}
	}
	this->current = NULL;
	return FALSE;
}

/**
 * Implementation of shared_enumerator_t.public.destroy
 */
static void shared_enumerator_destroy(shared_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of credential_set_t.create_shared_enumerator.
 */
static enumerator_t* create_shared_enumerator(private_sql_cred_t *this,
								  shared_key_type_t type, 
								  identification_t *me, identification_t *other)
{
	shared_enumerator_t *e;
	
	e = malloc_thing(shared_enumerator_t);
	e->me = me;
	e->other = other;
	e->current = NULL;
	e->public.enumerate = (void*)shared_enumerator_enumerate;
	e->public.destroy = (void*)shared_enumerator_destroy;
	if (!me && !other)
	{
		e->inner = this->db->query(this->db,
				"SELECT type, data FROM shared_secrets WHERE  (? OR type = ?)",
				DB_INT, type == SHARED_ANY, DB_INT, type,
				DB_INT, DB_BLOB);
	}
	else if (me && other)
	{
		e->inner = this->db->query(this->db,
				"SELECT s.type, s.data FROM shared_secrets AS s "
				"JOIN shared_secret_identity AS sm ON s.id = sm.shared_secret "
				"JOIN identities AS m ON sm.identity = m.id "
				"JOIN shared_secret_identity AS so ON s.id = so.shared_secret "
				"JOIN identities AS o ON so.identity = o.id "
				"WHERE m.type = ? AND m.data = ? AND o.type = ? AND o.data = ? "
				"AND (? OR s.type = ?)",
				DB_INT, me->get_type(me), DB_BLOB, me->get_encoding(me),
				DB_INT, other->get_type(other), DB_BLOB, other->get_encoding(other),
				DB_INT, type == SHARED_ANY, DB_INT, type,
				DB_INT, DB_BLOB);				
	}
	else
	{
		identification_t *id = me ? me : other;
		
		e->inner = this->db->query(this->db,
				"SELECT s.type, s.data FROM shared_secrets AS s "
				"JOIN shared_secret_identity AS si ON s.id = si.shared_secret "
				"JOIN identities AS i ON si.identity = i.id "
				"WHERE i.type = ? AND i.data = ? AND (? OR s.type = ?)",
				DB_INT, id->get_type(id), DB_BLOB, id->get_encoding(id),
				DB_INT, type == SHARED_ANY, DB_INT, type,
				DB_INT, DB_BLOB);
	}
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * Implementation of sql_cred_t.destroy.
 */
static void destroy(private_sql_cred_t *this)
{
	free(this);
}

/**
 * Described in header.
 */
sql_cred_t *sql_cred_create(database_t *db)
{
	private_sql_cred_t *this = malloc_thing(private_sql_cred_t);
	
	this->public.set.create_private_enumerator = (void*)create_private_enumerator;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.destroy = (void(*)(sql_cred_t*))destroy;
	
	this->db = db;
	
	return &this->public;
}

