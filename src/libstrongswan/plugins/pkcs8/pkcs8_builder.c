/*
 * Copyright (C) 2012 Tobias Brunner
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
 */

#include "pkcs8_builder.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <credentials/keys/private_key.h>

/**
 * ASN.1 definition of a privateKeyInfo structure
 */
static const asn1Object_t pkinfoObjects[] = {
	{ 0, "privateKeyInfo",			ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "version",				ASN1_INTEGER,		ASN1_BODY	}, /* 1 */
	{ 1,   "privateKeyAlgorithm",	ASN1_EOC,			ASN1_RAW	}, /* 2 */
	{ 1,   "privateKey",			ASN1_OCTET_STRING,	ASN1_BODY	}, /* 3 */
	{ 1,   "attributes",			ASN1_CONTEXT_C_0,	ASN1_OPT	}, /* 4 */
	{ 1,   "end opt",				ASN1_EOC,			ASN1_END	}, /* 5 */
	{ 0, "exit",					ASN1_EOC,			ASN1_EXIT	}
};
#define PKINFO_PRIVATE_KEY_ALGORITHM	2
#define PKINFO_PRIVATE_KEY				3

/**
 * Load a generic private key from an ASN.1 encoded blob
 */
static private_key_t *parse_private_key(chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object, params = chunk_empty;
	int objectID;
	private_key_t *key = NULL;
	key_type_t type = KEY_ANY;

	parser = asn1_parser_create(pkinfoObjects, blob);
	parser->set_flags(parser, FALSE, TRUE);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PKINFO_PRIVATE_KEY_ALGORITHM:
			{
				int oid = asn1_parse_algorithmIdentifier(object,
									parser->get_level(parser) + 1, &params);

				switch (oid)
				{
					case OID_RSA_ENCRYPTION:
						type = KEY_RSA;
						break;
					case OID_EC_PUBLICKEY:
						type = KEY_ECDSA;
						break;
					default:
						/* key type not supported */
						goto end;
				}
				break;
			}
			case PKINFO_PRIVATE_KEY:
			{
				DBG2(DBG_ASN, "-- > --");
				if (params.ptr)
				{
					key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
											 type, BUILD_BLOB_ALGID_PARAMS,
											 params, BUILD_BLOB_ASN1_DER,
											 object, BUILD_END);
				}
				else
				{
					key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
											 type, BUILD_BLOB_ASN1_DER, object,
											 BUILD_END);
				}
				DBG2(DBG_ASN, "-- < --");
				break;
			}
		}
	}

end:
	parser->destroy(parser);
	return key;
}

/**
 * See header.
 */
private_key_t *pkcs8_private_key_load(key_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	return parse_private_key(blob);
}

