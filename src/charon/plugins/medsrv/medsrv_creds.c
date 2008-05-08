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

#include "medsrv_creds.h"
#include "medsrv_pubkey.h"

#include <daemon.h>
#include <library.h>
#include <utils/enumerator.h>

typedef struct private_medsrv_creds_t private_medsrv_creds_t;

/**
 * Private data of an medsrv_creds_t object
 */
struct private_medsrv_creds_t {

	/**
	 * Public part
	 */
	medsrv_creds_t public;
	
	/**
	 * underlying database handle
	 */
	database_t *db;
};

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
	/** type of requested key */
	key_type_t type;
} cert_enumerator_t;

/**
 * Implementation of cert_enumerator_t.public.enumerate
 */
static bool cert_enumerator_enumerate(cert_enumerator_t *this,
									  certificate_t **cert)
{
	public_key_t *public;
	chunk_t chunk;

	DESTROY_IF(this->current);
	while (this->inner->enumerate(this->inner, &chunk))
	{
		public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
									BUILD_BLOB_ASN1_DER, chunk_clone(chunk),
									BUILD_END);
		if (public)
		{
			if (this->type == KEY_ANY || this->type == public->get_type(public))
			{
				*cert = this->current = (certificate_t*)medsrv_pubkey_create(public);
				return TRUE;
			}
			public->destroy(public);
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
static enumerator_t* create_cert_enumerator(private_medsrv_creds_t *this,
										certificate_type_t cert, key_type_t key,
										identification_t *id, bool trusted)
{
	cert_enumerator_t *e;
	
	if ((cert != CERT_TRUSTED_PUBKEY && cert != CERT_ANY) ||
		id == NULL || id->get_type(id) != ID_KEY_ID)
	{
		return NULL;
	}
	
	e = malloc_thing(cert_enumerator_t);
	e->current = NULL;
	e->type = key;
	e->public.enumerate = (void*)cert_enumerator_enumerate;
	e->public.destroy = (void*)cert_enumerator_destroy;
	e->inner = this->db->query(this->db,
							   "SELECT PublicKey FROM Peer WHERE KeyId = ?",
							   DB_BLOB, id->get_encoding(id),
							   DB_BLOB);
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * Implementation of backend_t.destroy.
 */
static void destroy(private_medsrv_creds_t *this)
{
    free(this);
}

/**
 * Described in header.
 */
medsrv_creds_t *medsrv_creds_create(database_t *db)
{
	private_medsrv_creds_t *this = malloc_thing(private_medsrv_creds_t);

	this->public.set.create_private_enumerator = (void*)return_null;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)return_null;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)nop;

	this->public.destroy = (void (*)(medsrv_creds_t*))destroy;
	
	this->db = db;
	
	return &this->public;
}

