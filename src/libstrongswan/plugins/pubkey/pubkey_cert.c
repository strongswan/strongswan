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

#include "pubkey_cert.h"

#include <debug.h>

/**
 * defined in pubkey_public_key.c
 */
extern public_key_t *pubkey_public_key_load(chunk_t blob);

typedef struct private_pubkey_cert_t private_pubkey_cert_t;

/**
 * private data of pubkey_cert
 */
struct private_pubkey_cert_t {

	/**
	 * public functions
	 */
	pubkey_cert_t public;
	
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
static certificate_type_t get_type(private_pubkey_cert_t *this)
{
	return CERT_TRUSTED_PUBKEY;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_pubkey_cert_t *this)
{
	return this->key->get_id(this->key, ID_PUBKEY_SHA1);
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_pubkey_cert_t *this)
{
	return this->issuer;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_pubkey_cert_t *this,
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
static id_match_t has_issuer(private_pubkey_cert_t *this,
							 identification_t *issuer)
{
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_pubkey_cert_t *this, certificate_t *other)
{
	if (this == (private_pubkey_cert_t*)other)
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
static bool issued_by(private_pubkey_cert_t *this, certificate_t *issuer)
{
	return equals(this, issuer);
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_pubkey_cert_t *this)
{
	this->key->get_ref(this->key);
	return this->key;
}
/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_pubkey_cert_t *this, time_t *when,
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
static chunk_t get_encoding(private_pubkey_cert_t *this)
{
	return this->key->get_encoding(this->key);
}

/**
 * Implementation of certificate_t.get_ref
 */
static private_pubkey_cert_t* get_ref(private_pubkey_cert_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of pubkey_cert_t.destroy
 */
static void destroy(private_pubkey_cert_t *this)
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
static pubkey_cert_t *pubkey_cert_create(public_key_t *key)
{
	private_pubkey_cert_t *this = malloc_thing(private_pubkey_cert_t);
	
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

static pubkey_cert_t *pubkey_cert_create_from_chunk(chunk_t blob)
{
	public_key_t *key = pubkey_public_key_load(chunk_clone(blob));

	return (key)? pubkey_cert_create(key) : NULL;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded public key */
	pubkey_cert_t *key;
};

/**
 * Implementation of builder_t.build
 */
static pubkey_cert_t *build(private_builder_t *this)
{
	pubkey_cert_t *key = this->key;
	
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	if (!this->key)
	{
		va_list args;
	
		switch (part)
		{
			case BUILD_BLOB_ASN1_DER:
			{
				va_start(args, part);
				this->key = pubkey_cert_create_from_chunk(va_arg(args, chunk_t));
				va_end(args);
				return;
			}
			case BUILD_PUBLIC_KEY:
			{
				va_start(args, part);
				this->key = pubkey_cert_create(va_arg(args, public_key_t*));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_pubkey_cert_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *pubkey_cert_builder(certificate_type_t type)
{
	private_builder_t *this;
	
	if (type != CERT_TRUSTED_PUBKEY)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->key = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

