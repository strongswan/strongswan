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

#include <utils/debug.h>
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
 * Prototype for key derivation functions.
 */
typedef bool (*kdf_t)(void *generator, chunk_t password, chunk_t salt,
					  u_int64_t iterations, chunk_t key);

/**
 * Try to decrypt the given blob with multiple passwords using the given
 * key derivation function. keymat is where the kdf function writes the key
 * to, key and iv point to the actual keys and initialization vectors resp.
 */
static private_key_t *decrypt_private_key(chunk_t blob,
					encryption_algorithm_t encr, size_t key_len, kdf_t kdf,
					void *generator, chunk_t salt, u_int64_t iterations,
					chunk_t keymat, chunk_t key, chunk_t iv)
{
	enumerator_t *enumerator;
	shared_key_t *shared;
	crypter_t *crypter;
	private_key_t *private_key = NULL;

	crypter = lib->crypto->create_crypter(lib->crypto, encr, key_len);
	if (!crypter)
	{
		DBG1(DBG_ASN, "  %N encryption algorithm not available",
			 encryption_algorithm_names, encr);
		return NULL;
	}
	if (blob.len % crypter->get_block_size(crypter))
	{
		DBG1(DBG_ASN, "  data size is not a multiple of block size");
		crypter->destroy(crypter);
		return NULL;
	}

	enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
										SHARED_PRIVATE_KEY_PASS, NULL, NULL);
	while (enumerator->enumerate(enumerator, &shared, NULL, NULL))
	{
		chunk_t decrypted;

		if (!kdf(generator, shared->get_key(shared), salt, iterations, keymat))
		{
			continue;
		}
		if (!crypter->set_key(crypter, key) ||
			!crypter->decrypt(crypter, blob, iv, &decrypted))
		{
			continue;
		}
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
	crypter->destroy(crypter);

	return private_key;
}

/**
 * Function F of PBKDF2
 */
static bool pbkdf2_f(chunk_t block, prf_t *prf, chunk_t seed,
					 u_int64_t iterations)
{
	chunk_t u;
	u_int64_t i;

	u = chunk_alloca(prf->get_block_size(prf));
	if (!prf->get_bytes(prf, seed, u.ptr))
	{
		return FALSE;
	}
	memcpy(block.ptr, u.ptr, block.len);

	for (i = 1; i < iterations; i++)
	{
		if (!prf->get_bytes(prf, u, u.ptr))
		{
			return FALSE;
		}
		memxor(block.ptr, u.ptr, block.len);
	}
	return TRUE;
}

/**
 * PBKDF2 key derivation function
 */
static bool pbkdf2(prf_t *prf, chunk_t password, chunk_t salt,
				   u_int64_t iterations, chunk_t key)
{
	chunk_t keymat, block, seed;
	size_t blocks;
	u_int32_t i = 0, *ni;

	if (!prf->set_key(prf, password))
	{
		return FALSE;
	}

	block.len = prf->get_block_size(prf);
	blocks = (key.len - 1) / block.len + 1;
	keymat = chunk_alloca(blocks * block.len);

	seed = chunk_cata("cc", salt, chunk_from_thing(i));
	ni = (u_int32_t*)(seed.ptr + salt.len);

	for (; i < blocks; i++)
	{
		*ni = htonl(i + 1);
		block.ptr = keymat.ptr + (i * block.len);
		if (!pbkdf2_f(block, prf, seed, iterations))
		{
			return FALSE;
		}
	}

	memcpy(key.ptr, keymat.ptr, key.len);

	return TRUE;
}

/**
 * Decrypt an encrypted PKCS#8 encoded private key according to PBES2
 */
static private_key_t *decrypt_private_key_pbes2(chunk_t blob,
							encryption_algorithm_t encr, size_t key_len,
							chunk_t iv, pseudo_random_function_t prf_func,
							chunk_t salt, u_int64_t iterations)
{
	private_key_t *private_key;
	prf_t *prf;
	chunk_t key;

	prf = lib->crypto->create_prf(lib->crypto, prf_func);
	if (!prf)
	{
		DBG1(DBG_ASN, "  %N prf algorithm not available",
			 pseudo_random_function_names, prf_func);
		return NULL;
	}

	key = chunk_alloca(key_len);

	private_key = decrypt_private_key(blob, encr, key_len, (kdf_t)pbkdf2, prf,
									  salt, iterations, key, key, iv);

	prf->destroy(prf);
	return private_key;
}

/**
 * PBKDF1 key derivation function
 */
static bool pbkdf1(hasher_t *hasher, chunk_t password, chunk_t salt,
				   u_int64_t iterations, chunk_t key)
{
	chunk_t hash;
	u_int64_t i;

	hash = chunk_alloca(hasher->get_hash_size(hasher));
	if (!hasher->get_hash(hasher, password, NULL) ||
		!hasher->get_hash(hasher, salt, hash.ptr))
	{
		return FALSE;
	}

	for (i = 1; i < iterations; i++)
	{
		if (!hasher->get_hash(hasher, hash, hash.ptr))
		{
			return FALSE;
		}
	}

	memcpy(key.ptr, hash.ptr, key.len);

	return TRUE;
}

/**
 * Decrypt an encrypted PKCS#8 encoded private key according to PBES1
 */
static private_key_t *decrypt_private_key_pbes1(chunk_t blob,
							encryption_algorithm_t encr, size_t key_len,
							hash_algorithm_t hash, chunk_t salt,
							u_int64_t iterations)
{
	private_key_t *private_key = NULL;
	hasher_t *hasher = NULL;
	chunk_t keymat, key, iv;

	hasher = lib->crypto->create_hasher(lib->crypto, hash);
	if (!hasher)
	{
		DBG1(DBG_ASN, "  %N hash algorithm not available",
			 hash_algorithm_names, hash);
		goto end;
	}
	if (hasher->get_hash_size(hasher) < key_len)
	{
		goto end;
	}

	keymat = chunk_alloca(key_len * 2);
	key.len = key_len;
	key.ptr = keymat.ptr;
	iv.len = key_len;
	iv.ptr = keymat.ptr + key_len;

	private_key = decrypt_private_key(blob, encr, key_len, (kdf_t)pbkdf1,
									  hasher, salt, iterations, keymat,
									  key, iv);

end:
	DESTROY_IF(hasher);
	return private_key;
}

/**
 * Parse an ASN1_INTEGER to a u_int64_t.
 */
static u_int64_t parse_asn1_integer_uint64(chunk_t blob)
{
	u_int64_t val = 0;
	int i;

	for (i = 0; i < blob.len; i++)
	{	/* if it is longer than 8 bytes, we just use the 8 LSBs */
		val <<= 8;
		val |= (u_int64_t)blob.ptr[i];
	}
	return val;
}

/**
 * ASN.1 definition of a PBKDF2-params structure
 * The salt is actually a CHOICE and could be an AlgorithmIdentifier from
 * PBKDF2-SaltSources (but as per RFC 2898 that's for future versions).
 */
static const asn1Object_t pbkdf2ParamsObjects[] = {
	{ 0, "PBKDF2-params",	ASN1_SEQUENCE,		ASN1_NONE			}, /* 0 */
	{ 1,   "salt",			ASN1_OCTET_STRING,	ASN1_BODY			}, /* 1 */
	{ 1,   "iterationCount",ASN1_INTEGER,		ASN1_BODY			}, /* 2 */
	{ 1,   "keyLength",		ASN1_INTEGER,		ASN1_OPT|ASN1_BODY	}, /* 3 */
	{ 1,   "end opt",		ASN1_EOC,			ASN1_END			}, /* 4 */
	{ 1,   "prf",			ASN1_EOC,			ASN1_DEF|ASN1_RAW	}, /* 5 */
	{ 0, "exit",			ASN1_EOC,			ASN1_EXIT			}
};
#define PBKDF2_SALT					1
#define PBKDF2_ITERATION_COUNT		2
#define PBKDF2_KEY_LENGTH			3
#define PBKDF2_PRF					5

/**
 * Parse a PBKDF2-params structure
 */
static void parse_pbkdf2_params(chunk_t blob, chunk_t *salt,
								u_int64_t *iterations, size_t *key_len,
								pseudo_random_function_t *prf)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(pbkdf2ParamsObjects, blob);

	*key_len = 0; /* key_len is optional */

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PBKDF2_SALT:
			{
				*salt = object;
				break;
			}
			case PBKDF2_ITERATION_COUNT:
			{
				*iterations = parse_asn1_integer_uint64(object);
				break;
			}
			case PBKDF2_KEY_LENGTH:
			{
				*key_len = (size_t)parse_asn1_integer_uint64(object);
				break;
			}
			case PBKDF2_PRF:
			{	/* defaults to id-hmacWithSHA1 */
				*prf = PRF_HMAC_SHA1;
				break;
			}
		}
	}

	parser->destroy(parser);
}

/**
 * ASN.1 definition of a PBES2-params structure
 */
static const asn1Object_t pbes2ParamsObjects[] = {
	{ 0, "PBES2-params",		ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "keyDerivationFunc",	ASN1_EOC,			ASN1_RAW	}, /* 1 */
	{ 1,   "encryptionScheme",	ASN1_EOC,			ASN1_RAW	}, /* 2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT	}
};
#define PBES2PARAMS_KEY_DERIVATION_FUNC		1
#define PBES2PARAMS_ENCRYPTION_SCHEME		2

/**
 * Parse a PBES2-params structure
 */
static void parse_pbes2_params(chunk_t blob, chunk_t *salt,
							   u_int64_t *iterations, size_t *key_len,
							   pseudo_random_function_t *prf,
							   encryption_algorithm_t *encr, chunk_t *iv)
{
	asn1_parser_t *parser;
	chunk_t object, params;
	int objectID;

	parser = asn1_parser_create(pbes2ParamsObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PBES2PARAMS_KEY_DERIVATION_FUNC:
			{
				int oid = asn1_parse_algorithmIdentifier(object,
									parser->get_level(parser) + 1, &params);
				if (oid != OID_PBKDF2)
				{	/* unsupported key derivation function */
					goto end;
				}
				parse_pbkdf2_params(params, salt, iterations, key_len, prf);
				break;
			}
			case PBES2PARAMS_ENCRYPTION_SCHEME:
			{
				int oid = asn1_parse_algorithmIdentifier(object,
									parser->get_level(parser) + 1, &params);
				if (oid != OID_3DES_EDE_CBC)
				{	/* unsupported encryption scheme */
					goto end;
				}
				if (*key_len <= 0)
				{	/* default key len for DES-EDE3-CBC-Pad */
					*key_len = 24;
				}
				if (!asn1_parse_simple_object(&params, ASN1_OCTET_STRING,
									parser->get_level(parser) + 1, "IV"))
				{
					goto end;
				}
				*encr = ENCR_3DES;
				*iv = params;
				break;
			}
		}
	}

end:
	parser->destroy(parser);
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
				*iterations = parse_asn1_integer_uint64(object);
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
 * Schemes per PKCS#5 (RFC 2898)
 */
static private_key_t *parse_encrypted_private_key(chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object, params, salt = chunk_empty, iv = chunk_empty;
	u_int64_t iterations = 0;
	int objectID;
	encryption_algorithm_t encr = ENCR_UNDEFINED;
	hash_algorithm_t hash = HASH_UNKNOWN;
	pseudo_random_function_t prf = PRF_UNDEFINED;
	private_key_t *key = NULL;
	size_t key_len = 8;

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
						parse_pbe_parameters(params, &salt, &iterations);
						break;
					case OID_PBE_SHA1_DES_CBC:
						encr = ENCR_DES;
						hash = HASH_SHA1;
						parse_pbe_parameters(params, &salt, &iterations);
						break;
					case OID_PBES2:
						parse_pbes2_params(params, &salt, &iterations,
										   &key_len, &prf, &encr, &iv);
						break;
					default:
						/* encryption scheme not supported */
						goto end;
				}
				break;
			}
			case EPKINFO_ENCRYPTED_DATA:
			{
				if (prf != PRF_UNDEFINED)
				{
					key = decrypt_private_key_pbes2(object, encr, key_len, iv,
													prf, salt, iterations);
				}
				else
				{
					key = decrypt_private_key_pbes1(object, encr, key_len, hash,
													salt, iterations);
				}
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

