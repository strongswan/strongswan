/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2008 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#include <library.h>
#include <utils/debug.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <collections/linked_list.h>

#include "pkcs9.h"

typedef struct private_pkcs9_t private_pkcs9_t;
typedef struct attribute_t attribute_t;

/**
 * Private data of a pkcs9_t attribute list.
 */
struct private_pkcs9_t {
	/**
	 * Public interface
	 */
	pkcs9_t public;

	/**
	 * DER encoding of PKCS#9 attributes
	 */
	chunk_t encoding;

	/**
	 * Linked list of PKCS#9 attributes
	 */
	linked_list_t *attributes;
};

/**
 * Definition of an attribute_t object.
 */
struct attribute_t {

	/**
	 * Object Identifier (OID)
	 */
	int oid;

	/**
	 * Attribute value
	 */
	chunk_t value;

	/**
	 * ASN.1 encoding
	 */
	chunk_t encoding;
};

/**
 * return the ASN.1 encoding of a PKCS#9 attribute
 */
static asn1_t get_attribute_type(int oid)
{
	switch (oid)
	{
		case OID_PKCS9_CONTENT_TYPE:
			return ASN1_OID;
		case OID_PKCS9_SIGNING_TIME:
			return ASN1_UTCTIME;
		case OID_PKI_MESSAGE_TYPE:
		case OID_PKI_STATUS:
		case OID_PKI_FAIL_INFO:
			return ASN1_PRINTABLESTRING;
		case OID_PKI_SENDER_NONCE:
		case OID_PKI_RECIPIENT_NONCE:
		case OID_PKCS9_MESSAGE_DIGEST:
			return ASN1_OCTET_STRING;
		case OID_PKI_TRANS_ID:
			return ASN1_PRINTABLESTRING;
		default:
			return ASN1_EOC;
	}
}

/**
 * Destroy an attribute_t object.
 */
static void attribute_destroy(attribute_t *this)
{
	free(this->value.ptr);
	free(this->encoding.ptr);
	free(this);
}

/**
 * Create an attribute_t object.
 */
static attribute_t *attribute_create(int oid, chunk_t value)
{
	attribute_t *this;

	INIT(this,
		.oid = oid,
		.value = chunk_clone(value),
		.encoding = asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_build_known_oid(oid),
						asn1_wrap(ASN1_SET, "c", value)),
	);

	return this;
}

/**
 * Build encoding of the attribute list
 */
static void build_encoding(private_pkcs9_t *this)
{
	enumerator_t *enumerator;
	attribute_t *attribute;
	u_int len = 0;
	u_char *pos;

	/* compute the total length of the encoded attributes */
	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		len += attribute->encoding.len;
	}
	enumerator->destroy(enumerator);

	/* allocate memory for the attributes and build the encoding */
	pos = asn1_build_object(&this->encoding, ASN1_SET, len);
	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		memcpy(pos, attribute->encoding.ptr, attribute->encoding.len);
		pos += attribute->encoding.len;
	}
	enumerator->destroy(enumerator);
}

METHOD(pkcs9_t, get_encoding, chunk_t,
	private_pkcs9_t *this)
{
	if (!this->encoding.len)
	{
		build_encoding(this);
	}
	return this->encoding;
}

METHOD(pkcs9_t, get_attribute, chunk_t,
	private_pkcs9_t *this, int oid)
{
	enumerator_t *enumerator;
	chunk_t value = chunk_empty;
	attribute_t *attribute;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		if (attribute->oid == oid)
		{
			value = attribute->value;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (value.len && asn1_unwrap(&value, &value) != ASN1_INVALID)
	{
		return value;
	}
	return chunk_empty;
}

METHOD(pkcs9_t, set_attribute_raw, void,
	private_pkcs9_t *this, int oid, chunk_t value)
{
	attribute_t *attribute = attribute_create(oid, value);

	this->attributes->insert_last(this->attributes, attribute);
	chunk_free(&value);
}

METHOD(pkcs9_t, set_attribute, void,
	private_pkcs9_t *this, int oid, chunk_t value)
{
	chunk_t attr = asn1_simple_object(get_attribute_type(oid), value);

	set_attribute_raw(this, oid, attr);
}

METHOD(pkcs9_t, destroy, void,
	private_pkcs9_t *this)
{
	this->attributes->destroy_function(this->attributes,
									   (void*)attribute_destroy);
	free(this->encoding.ptr);
	free(this);
}

/*
 * Described in header.
 */
pkcs9_t *pkcs9_create(void)
{
	private_pkcs9_t *this;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.get_attribute = _get_attribute,
			.set_attribute = _set_attribute,
			.set_attribute_raw = _set_attribute_raw,
			.destroy = _destroy,
		},
		.attributes = linked_list_create(),
	);

	return &this->public;
}

/**
 * ASN.1 definition of the X.501 atttribute type
 */
static const asn1Object_t attributesObjects[] = {
	{ 0, "attributes",		ASN1_SET,		ASN1_LOOP }, /* 0 */
	{ 1,   "attribute",		ASN1_SEQUENCE,	ASN1_NONE }, /* 1 */
	{ 2,     "type",		ASN1_OID,		ASN1_BODY }, /* 2 */
	{ 2,     "values",		ASN1_SET,		ASN1_LOOP }, /* 3 */
	{ 3,       "value",		ASN1_EOC,		ASN1_RAW  }, /* 4 */
	{ 2,     "end loop",	ASN1_EOC,		ASN1_END  }, /* 5 */
	{ 0, "end loop",		ASN1_EOC,		ASN1_END  }, /* 6 */
	{ 0, "exit",			ASN1_EOC,		ASN1_EXIT }
};
#define ATTRIBUTE_OBJ_TYPE 	2
#define ATTRIBUTE_OBJ_VALUE	4

/**
 * Parse a PKCS#9 attribute list
 */
static bool parse_attributes(chunk_t chunk, int level0, private_pkcs9_t* this)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int oid = OID_UNKNOWN;
	bool success = FALSE;

	parser = asn1_parser_create(attributesObjects, chunk);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case ATTRIBUTE_OBJ_TYPE:
				oid = asn1_known_oid(object);
				break;
			case ATTRIBUTE_OBJ_VALUE:
				if (oid != OID_UNKNOWN)
				{
					this->attributes->insert_last(this->attributes,
												  attribute_create(oid, object));
				}
				break;
		}
	}
	success = parser->success(parser);

	parser->destroy(parser);
	return success;
}

 /*
 * Described in header.
 */
pkcs9_t *pkcs9_create_from_chunk(chunk_t chunk, u_int level)
{
	private_pkcs9_t *this = (private_pkcs9_t*)pkcs9_create();

	this->encoding = chunk_clone(chunk);
	if (!parse_attributes(chunk, level, this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
