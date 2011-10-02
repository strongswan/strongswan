/*
 * Copyright (C)2008 Andreas Steffen
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
#include <debug.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <utils/linked_list.h>

#include "pkcs9.h"

typedef struct private_pkcs9_t private_pkcs9_t;

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

typedef struct attribute_t attribute_t;

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

	/**
	 * Destroys the attribute.
	 */
	void (*destroy) (attribute_t *this);

};

/**
 * PKCS#9 attribute type OIDs
 */
static chunk_t ASN1_contentType_oid = chunk_from_chars(
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03
);
static chunk_t ASN1_messageDigest_oid = chunk_from_chars(
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04
);
static chunk_t ASN1_signingTime_oid = chunk_from_chars(
	0x06, 0x09,
		  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05
);
static chunk_t ASN1_messageType_oid = chunk_from_chars(
	0x06, 0x0A,
		  0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02
);
static chunk_t ASN1_senderNonce_oid = chunk_from_chars(
	0x06, 0x0A,
		  0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05
);
static chunk_t ASN1_transId_oid = chunk_from_chars(
	0x06, 0x0A,
		  0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07
);

/**
 * return the ASN.1 encoded OID of a PKCS#9 attribute
 */
static chunk_t asn1_attributeIdentifier(int oid)
{
	switch (oid)
	{
		case OID_PKCS9_CONTENT_TYPE:
			return ASN1_contentType_oid;
		case OID_PKCS9_MESSAGE_DIGEST:
			return ASN1_messageDigest_oid;
		case OID_PKCS9_SIGNING_TIME:
			return ASN1_signingTime_oid;
		case OID_PKI_MESSAGE_TYPE:
			return ASN1_messageType_oid;
		case OID_PKI_SENDER_NONCE:
			return ASN1_senderNonce_oid;
		case OID_PKI_TRANS_ID:
			return ASN1_transId_oid;;
		default:
			return chunk_empty;
	}
}

/**
 * return the ASN.1 encoding of a PKCS#9 attribute
 */
static asn1_t asn1_attributeType(int oid)
{
	asn1_t type;

	switch (oid)
	{
		case OID_PKCS9_CONTENT_TYPE:
			type = ASN1_OID;
			break;
		case OID_PKCS9_SIGNING_TIME:
			type = ASN1_UTCTIME;
			break;
		case OID_PKCS9_MESSAGE_DIGEST:
			type = ASN1_OCTET_STRING;
			break;
		case OID_PKI_MESSAGE_TYPE:
			type = ASN1_PRINTABLESTRING;
			break;
		case OID_PKI_STATUS:
			type = ASN1_PRINTABLESTRING;
			break;
		case OID_PKI_FAIL_INFO:
			type = ASN1_PRINTABLESTRING;
			break;
		case OID_PKI_SENDER_NONCE:
			type = ASN1_OCTET_STRING;
			break;
		case OID_PKI_RECIPIENT_NONCE:
			type = ASN1_OCTET_STRING;
			break;
		case OID_PKI_TRANS_ID:
			type = ASN1_PRINTABLESTRING;
			break;
		default:
			type = ASN1_EOC;
	}
	return type;
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
		.destroy = attribute_destroy,
		.oid = oid,
		.value = chunk_clone(value),
		.encoding = asn1_wrap(ASN1_SEQUENCE, "cm",
							asn1_attributeIdentifier(oid),
							asn1_simple_object(ASN1_SET, value)),
	);

	return this;
}

METHOD(pkcs9_t, build_encoding, void,
	private_pkcs9_t *this)
{
	enumerator_t *enumerator;
	attribute_t *attribute;
	u_int attributes_len = 0;

	if (this->encoding.ptr)
	{
		chunk_free(&this->encoding);
	}
	if (this->attributes->get_count(this->attributes) == 0)
	{
		return;
	}

	/* compute the total length of the encoded attributes */
	enumerator = this->attributes->create_enumerator(this->attributes);

	while (enumerator->enumerate(enumerator, (void**)&attribute))
	{
		attributes_len += attribute->encoding.len;
	}
	enumerator->destroy(enumerator);

	/* allocate memory for the attributes and build the encoding */
	{
		u_char *pos = asn1_build_object(&this->encoding, ASN1_SET, attributes_len);

		enumerator = this->attributes->create_enumerator(this->attributes);

		while (enumerator->enumerate(enumerator, (void**)&attribute))
		{
			memcpy(pos, attribute->encoding.ptr, attribute->encoding.len);
			pos += attribute->encoding.len;
		}
		enumerator->destroy(enumerator);
	}
}

METHOD(pkcs9_t, get_encoding, chunk_t,
	private_pkcs9_t *this)
{
	if (this->encoding.ptr == NULL)
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
	while (enumerator->enumerate(enumerator, (void**)&attribute))
	{
		if (attribute->oid == oid)
		{
			value = attribute->value;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return value;
}

METHOD(pkcs9_t, set_attribute, void,
	private_pkcs9_t *this, int oid, chunk_t value)
{
	attribute_t *attribute = attribute_create(oid, value);

	this->attributes->insert_last(this->attributes, (void*)attribute);
}

METHOD(pkcs9_t, get_messageDigest, chunk_t,
	private_pkcs9_t *this)
{
	const int oid = OID_PKCS9_MESSAGE_DIGEST;
	chunk_t value = get_attribute(this, oid);

	if (value.ptr == NULL)
	{
		return chunk_empty;
	}
	if (!asn1_parse_simple_object(&value, asn1_attributeType(oid), 0,
								  oid_names[oid].name))
	{
		return chunk_empty;
	}
	return chunk_clone(value);
}

METHOD(pkcs9_t, set_messageDigest, void,
	private_pkcs9_t *this, chunk_t value)
{
	const int oid = OID_PKCS9_MESSAGE_DIGEST;
	chunk_t messageDigest = asn1_simple_object(asn1_attributeType(oid), value);

	set_attribute(this, oid, messageDigest);
	free(messageDigest.ptr);
}

METHOD(pkcs9_t, destroy, void,
	private_pkcs9_t *this)
{
	this->attributes->destroy_offset(this->attributes, offsetof(attribute_t, destroy));
	free(this->encoding.ptr);
	free(this);
}

/**
 * Generic private constructor
 */
static private_pkcs9_t *pkcs9_create_empty(void)
{
	private_pkcs9_t *this;

	INIT(this,
		.public = {
			.build_encoding = _build_encoding,
			.get_encoding = _get_encoding,
			.get_attribute = _get_attribute,
			.set_attribute = _set_attribute,
			.get_messageDigest = _get_messageDigest,
			.set_messageDigest = _set_messageDigest,
			.destroy = _destroy,
		},
		.attributes = linked_list_create(),
	);

	return this;
}

/*
 * Described in header.
 */
pkcs9_t *pkcs9_create(void)
{
	private_pkcs9_t *this = pkcs9_create_empty();

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
				if (oid == OID_UNKNOWN)
				{
					break;
				}
				/* add the attribute to a linked list */
				{
					attribute_t *attribute = attribute_create(oid, object);

					this->attributes->insert_last(this->attributes,
												 (void*)attribute);
				}
				/* parse known attributes  */
				{
					asn1_t type = asn1_attributeType(oid);

					if (type != ASN1_EOC)
					{
						if (!asn1_parse_simple_object(&object, type,
										parser->get_level(parser)+1,
										oid_names[oid].name))
						{
							goto end;
						}
					}
				}
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}


 /*
 * Described in header.
 */
pkcs9_t *pkcs9_create_from_chunk(chunk_t chunk, u_int level)
{
	private_pkcs9_t *this = pkcs9_create_empty();

	this->encoding = chunk_clone(chunk);

	if (!parse_attributes(chunk, level, this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
