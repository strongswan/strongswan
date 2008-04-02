/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2000-2006 Andreas Steffen
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

#include "gmp_public_key.h"

#include <asn1/asn1.h>
#include <debug.h>

/**
 * ASN.1 definition of a subjectPublicKeyInfo structure
 */
static const asn1Object_t pkinfoObjects[] = {
	{ 0, "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "algorithm",			ASN1_EOC,			ASN1_RAW	}, /* 1 */
	{ 1,   "subjectPublicKey",	ASN1_BIT_STRING,	ASN1_NONE	}, /* 2 */
	{ 2,     "publicKey",		ASN1_SEQUENCE,		ASN1_RAW	}, /* 3 */
};
#define PKINFO								0
#define PKINFO_SUBJECT_PUBLIC_KEY_ALGORITHM	1
#define PKINFO_SUBJECT_PUBLIC_KEY			2
#define PKINFO_PUBLIC_KEY					3
#define PKINFO_ROOF							4

/**
 * Load a public key from an ASN1 encoded blob
 */
static public_key_t *load(chunk_t blob)
{
	asn1_ctx_t ctx;
	chunk_t object, data = chunk_empty;
	u_int level;
	int objectID = 0;
	key_type_t type = KEY_ANY;
	
	asn1_init(&ctx, blob, 0, FALSE, FALSE);
	
	while (objectID < PKINFO_ROOF) 
	{
		if (!extract_object(pkinfoObjects, &objectID, &object, &level, &ctx))
		{
			free(blob.ptr);
			return NULL;
		}
		switch (objectID)
		{
			case PKINFO_SUBJECT_PUBLIC_KEY_ALGORITHM:
				switch (parse_algorithmIdentifier(object, level, NULL))
				{
					case OID_RSA_ENCRYPTION:
						type = KEY_RSA;
						break;
					default:
						break;
				}
				break;
			case PKINFO_SUBJECT_PUBLIC_KEY:
				if (ctx.blobs[2].len > 0 && *ctx.blobs[2].ptr == 0x00)
				{	/* skip initial bit string octet defining 0 unused bits */
					ctx.blobs[2].ptr++; ctx.blobs[2].len--;
				}
				break;
			case PKINFO_PUBLIC_KEY:
				data = chunk_clone(object);
				break;
		}
		objectID++;
	}
	free(blob.ptr);
	if (type == KEY_ANY)
	{
		free(data.ptr);
		return NULL;
	}
	return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, type,
							  BUILD_BLOB_ASN1_DER, data, BUILD_END);
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded public key */
	public_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static public_key_t *build(private_builder_t *this)
{
	public_key_t *key = this->key;
	
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	if (this->key)
	{
		DBG1("ignoring surplus build part %N", builder_part_names, part);
		return;
	}
	switch (part)
	{
		case BUILD_BLOB_ASN1_DER:
		{
			va_start(args, part);
			this->key = load(va_arg(args, chunk_t));
			va_end(args);
			break;
		}
		default:
			DBG1("ignoring unsupported build part %N", builder_part_names, part);
			break;
	}
}

/**
 * Builder construction function
 */
builder_t *gmp_public_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_ANY)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->key = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

