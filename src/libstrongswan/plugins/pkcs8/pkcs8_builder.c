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
 * Verify padding of decrypted blob.
 * Length of blob is adjusted accordingly.
 */
static bool verify_padding(chunk_t *blob)
{
	u_int8_t padding, count;

	padding = count = blob->ptr[blob->len - 1];
	if (padding > 8)
	{
		return FALSE;
	}
	for (; blob->len && count; --blob->len, --count)
	{
		if (blob->ptr[blob->len - 1] != padding)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * PBKDF1 key derivation function
 */
static void pbkdf1(hasher_t *hasher, chunk_t password, chunk_t salt,
				   u_int64_t iterations, chunk_t key)
{
	chunk_t hash;
	u_int64_t i;

	hash = chunk_alloca(hasher->get_hash_size(hasher));
	hasher->get_hash(hasher, password, NULL);
	hasher->get_hash(hasher, salt, hash.ptr);

	for (i = 1; i < iterations; i++)
	{
		hasher->get_hash(hasher, hash, hash.ptr);
	}

	memcpy(key.ptr, hash.ptr, key.len);
}

/**
 * Decrypt an encrypted PKCS#8 encoded private key
 */
static private_key_t *decrypt_private_key(chunk_t blob,
							encryption_algorithm_t encr, size_t key_size,
							hash_algorithm_t hash, chunk_t salt,
							u_int64_t iterations)
{
	enumerator_t *enumerator;
	shared_key_t *shared;
	private_key_t *private_key = NULL;
	crypter_t *crypter = NULL;
	hasher_t *hasher = NULL;
	chunk_t keymat, key, iv;

	hasher = lib->crypto->create_hasher(lib->crypto, hash);
	if (!hasher)
	{
		DBG1(DBG_ASN, "  %N hash algorithm not available",
			 hash_algorithm_names, hash);
		goto end;
	}
	if (hasher->get_hash_size(hasher) < key_size)
	{
		goto end;
	}

	crypter = lib->crypto->create_crypter(lib->crypto, encr, key_size);
	if (!crypter)
	{
		DBG1(DBG_ASN, "  %N encryption algorithm not available",
			 encryption_algorithm_names, encr);
		goto end;
	}
	if (blob.len % crypter->get_block_size(crypter))
	{
		DBG1(DBG_ASN, "  data size is not a multiple of block size");
		goto end;
	}

	keymat = chunk_alloca(key_size * 2);
	key.len = key_size;
	key.ptr = keymat.ptr;
	iv.len = key_size;
	iv.ptr = keymat.ptr + key_size;

	enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
										SHARED_PRIVATE_KEY_PASS, NULL, NULL);
	while (enumerator->enumerate(enumerator, &shared, NULL, NULL))
	{
		chunk_t decrypted;

		pbkdf1(hasher, shared->get_key(shared), salt, iterations, keymat);

		crypter->set_key(crypter, key);
		crypter->decrypt(crypter, blob, iv, &decrypted);
		if (verify_padding(&decrypted))
		{
			private_key = parse_private_key(decrypted);
			if (private_key)
			{
				chunk_clear(&decrypted);
				break;
			}
		}
		chunk_free(&decrypted);
	}
	enumerator->destroy(enumerator);

end:
	DESTROY_IF(crypter);
	DESTROY_IF(hasher);
	return private_key;
}

/**
 * ASN.1 definition of a PBEParameter structure
 */
static const asn1Object_t pbeParameterObjects[] = {
	{ 0, "PBEParameter",		ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "salt",				ASN1_OCTET_STRING,	ASN1_BODY	}, /* 1 */
	{ 1,   "iterationCount",	ASN1_INTEGER,		ASN1_BODY	}, /* 2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT	}
};
#define PBEPARAM_SALT					1
#define PBEPARAM_ITERATION_COUNT		2

/**
 * Parse a PBEParameter structure
 */
static void parse_pbe_parameters(chunk_t blob, chunk_t *salt,
								 u_int64_t *iterations)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(pbeParameterObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PBEPARAM_SALT:
			{
				*salt = object;
				break;
			}
			case PBEPARAM_ITERATION_COUNT:
			{
				u_int64_t val = 0;
				int i;

				for (i = 0; i < object.len; i++)
				{	/* if it is longer than 8 bytes, we just use the 8 LSBs */
					val <<= 8;
					val |= (u_int64_t)object.ptr[i];
				}
				*iterations = val;
				break;
			}
		}
	}

	parser->destroy(parser);
}

/**
 * ASN.1 definition of an encryptedPrivateKeyInfo structure
 */
static const asn1Object_t encryptedPKIObjects[] = {
	{ 0, "encryptedPrivateKeyInfo",	ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "encryptionAlgorithm",	ASN1_EOC,			ASN1_RAW	}, /* 1 */
	{ 1,   "encryptedData",			ASN1_OCTET_STRING,	ASN1_BODY	}, /* 2 */
	{ 0, "exit",					ASN1_EOC,			ASN1_EXIT	}
};
#define EPKINFO_ENCRYPTION_ALGORITHM	1
#define EPKINFO_ENCRYPTED_DATA			2

/**
 * Load an encrypted private key from an ASN.1 encoded blob
 * Schemes per PKCS#5 (RFC 2898), currently only a subset of PBES1 is supported
 */
static private_key_t *parse_encrypted_private_key(chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object, params = chunk_empty, salt;
	u_int64_t iterations;
	int objectID;
	encryption_algorithm_t encr = ENCR_UNDEFINED;
	hash_algorithm_t hash = HASH_UNKNOWN;
	private_key_t *key = NULL;
	size_t key_size;

	parser = asn1_parser_create(encryptedPKIObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case EPKINFO_ENCRYPTION_ALGORITHM:
			{
				int oid = asn1_parse_algorithmIdentifier(object,
									parser->get_level(parser) + 1, &params);

				switch (oid)
				{
					case OID_PBE_MD5_DES_CBC:
						encr = ENCR_DES;
						hash = HASH_MD5;
						key_size = 8;
						parse_pbe_parameters(params, &salt, &iterations);
						break;
					case OID_PBE_SHA1_DES_CBC:
						encr = ENCR_DES;
						hash = HASH_SHA1;
						key_size = 8;
						parse_pbe_parameters(params, &salt, &iterations);
						break;
					default:
						/* encryption scheme not supported */
						goto end;
				}
				break;
			}
			case EPKINFO_ENCRYPTED_DATA:
			{
				key = decrypt_private_key(object, encr, key_size, hash, salt,
										  iterations);
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
	private_key_t *key;

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
	/* we don't know whether it is encrypted or not, try both ways */
	key = parse_encrypted_private_key(blob);
	if (!key)
	{
		key = parse_private_key(blob);
	}
	return key;
}

