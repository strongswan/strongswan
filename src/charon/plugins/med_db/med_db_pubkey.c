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

#include "med_db_pubkey.h"

typedef struct private_med_db_pubkey_t private_med_db_pubkey_t;

/**
 * private data of med_db_pubkey
 */
struct private_med_db_pubkey_t {

	/**
	 * public functions
	 */
	med_db_pubkey_t public;
	
	/**
	 * wrapped public key
	 */
	public_key_t *key;
	
	/**
	 * dummy issuer id, ID_ANY
	 */
	identification_t *issuer;
	
	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_med_db_pubkey_t *this)
{
	return CERT_TRUSTED_PUBKEY;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_med_db_pubkey_t *this)
{
	return this->key->get_id(this->key, ID_PUBKEY_SHA1);
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_med_db_pubkey_t *this)
{
	return this->issuer;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_med_db_pubkey_t *this,
							  identification_t *subject)
{
	identification_t *id;
	
	id = this->key->get_id(this->key, subject->get_type(subject));
	if (id)
	{
		return id->matches(id, subject);
	}
	return ID_MATCH_NONE;	
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_issuer(private_med_db_pubkey_t *this,
							 identification_t *issuer)
{
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_med_db_pubkey_t *this, certificate_t *other)
{
	if (this == (private_med_db_pubkey_t*)other)
	{
		return TRUE;
	}
	if (other->get_type(other) != CERT_TRUSTED_PUBKEY)
	{
		return FALSE;
	}
	return other->has_subject(other, this->key->get_id(this->key, ID_PUBKEY_SHA1));
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_med_db_pubkey_t *this, certificate_t *issuer)
{
	return equals(this, issuer);
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_med_db_pubkey_t *this)
{
	this->key->get_ref(this->key);
	return this->key;
}
/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_med_db_pubkey_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	if (not_before)
	{
		*not_before = 0;
	}
	if (not_after)
	{
		*not_after = ~0;
	}
	return TRUE;
}

/**
 * Implementation of certificate_t.is_newer.
 */
static bool is_newer(certificate_t *this, certificate_t *that)
{
	return FALSE;
}
	
/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_med_db_pubkey_t *this)
{
	return this->key->get_encoding(this->key);
}

/**
 * Implementation of certificate_t.get_ref
 */
static private_med_db_pubkey_t* get_ref(private_med_db_pubkey_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of med_db_pubkey_t.destroy
 */
static void destroy(private_med_db_pubkey_t *this)
{
	if (ref_put(&this->ref))
	{
		this->issuer->destroy(this->issuer);
		this->key->destroy(this->key);
		free(this);
	}
}

/*
 * see header file
 */
med_db_pubkey_t *med_db_pubkey_create(public_key_t *key)
{
	private_med_db_pubkey_t *this = malloc_thing(private_med_db_pubkey_t);
	
	this->public.interface.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.get_subject = (identification_t* (*)(certificate_t *this))get_subject;
	this->public.interface.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.has_subject = (id_match_t (*)(certificate_t*, identification_t *subject))has_subject;
	this->public.interface.has_issuer = (id_match_t (*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.interface.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.get_validity = (bool (*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.is_newer = (bool (*)(certificate_t*,certificate_t*))is_newer;
	this->public.interface.get_encoding = (chunk_t (*)(certificate_t*))get_encoding;
	this->public.interface.equals = (bool (*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.destroy = (void (*)(certificate_t *this))destroy;
	
	this->ref = 1;
	this->key = key;
	this->issuer = identification_create_from_encoding(ID_ANY, chunk_empty);
	
	return &this->public;
}

