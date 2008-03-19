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

#include "med_db_creds.h"

#include <daemon.h>
#include <library.h>
#include <utils/enumerator.h>

typedef struct private_med_db_creds_t private_med_db_creds_t;

/**
 * Private data of an med_db_creds_t object
 */
struct private_med_db_creds_t {

	/**
	 * Public part
	 */
	med_db_creds_t public;
	
	/**
	 * underlying database handle
	 */
	database_t *db;
};

/**
 * data passed between enumerate calls
 */
typedef struct  {
	/** current shared key */
	shared_key_t *current;
} data_t;

typedef struct private_shared_key_t private_shared_key_t;
/**
 * shared key implementation
 */
struct private_shared_key_t {
	/** implements shared_key_t*/
	shared_key_t public;
	/** data of the key */
	chunk_t key;
	/** reference counter */
	refcount_t ref;
};

/**
 * Destroy allocated data_t struct
 */
static void data_destroy(data_t *this)
{
	DESTROY_IF(this->current);
	free(this);
}

/**
 * Implementation of shared_key_t.get_type.
 */
static shared_key_type_t get_type(private_shared_key_t *this)
{
	return SHARED_IKE;
}

/**
 * Implementation of shared_key_t.get_ref.
 */
static private_shared_key_t* get_ref(private_shared_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of shared_key_t.destroy
 */
static void shared_key_destroy(private_shared_key_t *this)
{
	if (ref_put(&this->ref))
	{
		chunk_free(&this->key);
		free(this);
	}
}

/**
 * Implementation of shared_key_t.get_key.
 */
static chunk_t get_key(private_shared_key_t *this)
{
	return this->key;
}

/**
 * create a shared key
 */
static shared_key_t *shared_key_create(chunk_t key)
{
	private_shared_key_t *this = malloc_thing(private_shared_key_t);

	this->public.get_type = (shared_key_type_t(*)(shared_key_t*))get_type;
	this->public.get_key = (chunk_t(*)(shared_key_t*))get_key;
	this->public.get_ref = (shared_key_t*(*)(shared_key_t*))get_ref;
	this->public.destroy = (void(*)(shared_key_t*))shared_key_destroy;

	this->key = chunk_clone(key);
	this->ref = 1;
	return &this->public;
}

/**
 * filter for enumerator, returns for each SQL result a shared key and match
 */
static bool filter(data_t *this, chunk_t *chunk, shared_key_t **out,
				   void **unused1, id_match_t *match_me,
				   void **unused2, id_match_t *match_other)
{
	DESTROY_IF(this->current);
	this->current = shared_key_create(*chunk);
	*out = this->current;
	/* we have unique matches only, but do not compare own ID */
	if (match_me)
	{
		*match_me = ID_MATCH_ANY;
	}
	if (match_other)
	{
		*match_other = ID_MATCH_PERFECT;
	}
	return TRUE;
}


/**
 * Implements credential_set_t.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(private_med_db_creds_t *this, 
							shared_key_type_t type,	identification_t *me,
							identification_t *other)
{
	enumerator_t *enumerator;
	data_t *data;
	
	if (type != SHARED_IKE)
	{
		return NULL;
	}
	enumerator = this->db->query(this->db,
								 "SELECT Psk FROM Peer WHERE PeerId = ?",
								 DB_BLOB, other->get_encoding(other),
								 DB_BLOB);
	if (enumerator)
	{
		data = malloc_thing(data_t);
		data->current = NULL;
		return enumerator_create_filter(enumerator,	(void*)filter,
										data, (void*)data_destroy);
	}
	return NULL;
}
	
/**
 * Implementation of backend_t.destroy.
 */
static void destroy(private_med_db_creds_t *this)
{
    free(this);
}

/**
 * Described in header.
 */
med_db_creds_t *med_db_creds_create(database_t *db)
{
	private_med_db_creds_t *this = malloc_thing(private_med_db_creds_t);

	this->public.set.create_private_enumerator = (void*)return_null;
	this->public.set.create_cert_enumerator = (void*)return_null;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;

	this->public.destroy = (void (*)(med_db_creds_t*))destroy;
	
	this->db = db;
	
	return &this->public;
}

