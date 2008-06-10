/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2000-2008 Andreas Steffen
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

#include "pubkey_public_key.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>

/**
 * ASN.1 definition of a subjectPublicKeyInfo structure
 */
static const asn1Object_t pkinfoObjects[] = {
	{ 0, "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "algorithm",			ASN1_EOC,			ASN1_RAW	}, /* 1 */
	{ 1,   "subjectPublicKey",	ASN1_BIT_STRING,	ASN1_BODY	}, /* 2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT	}
};
#define PKINFO_SUBJECT_PUBLIC_KEY_ALGORITHM	1
#define PKINFO_SUBJECT_PUBLIC_KEY			2


/**
 * Load a public key from an ASN1 encoded blob
 */
static public_key_t *load(chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	public_key_t *key = NULL;
	key_type_t type = KEY_ANY;

	parser = asn1_parser_create(pkinfoObjects, blob);
	
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PKINFO_SUBJECT_PUBLIC_KEY_ALGORITHM:
			{
				int oid = asn1_parse_algorithmIdentifier(object,
										parser->get_level(parser)+1, NULL);
				
				if (oid == OID_RSA_ENCRYPTION)
				{
					type = KEY_RSA;
				}
				else if (oid == OID_EC_PUBLICKEY)
				{
					/* we need the whole subjectPublicKeyInfo for EC public keys */
					key = lib->creds->create(lib->creds,
								CRED_PUBLIC_KEY, KEY_ECDSA, BUILD_BLOB_ASN1_DER,
								chunk_clone(blob), BUILD_END);
					goto end;
				}
				else
				{
					/* key type not supported */
					goto end;
				}
				break;
			}
			case PKINFO_SUBJECT_PUBLIC_KEY:
				if (object.len > 0 && *object.ptr == 0x00)
				{
					/* skip initial bit string octet defining 0 unused bits */
					object = chunk_skip(object, 1);
				}
				key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, type,
										 BUILD_BLOB_ASN1_DER, chunk_clone(object),
										 BUILD_END);
				break;
		}
	} 
	
end:
	parser->destroy(parser);
	free(blob.ptr);
	return key; 
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
builder_t *pubkey_public_key_builder(key_type_t type)
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

