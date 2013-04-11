/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

#include "pkcs5.h"

#include <utils/debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>

typedef struct private_pkcs5_t private_pkcs5_t;

/**
 * Private data of a pkcs5_t object
 */
struct private_pkcs5_t {

	/**
	 * Implements pkcs5_t.
	 */
	pkcs5_t public;

	/**
	 * Salt used during encryption
	 */
	chunk_t salt;

	/**
	 * Iterations for key derivation
	 */
	u_int64_t iterations;

	/**
	 * Encryption algorithm
	 */
	encryption_algorithm_t encr;

	/**
	 * Encryption key length
	 */
	size_t keylen;

	/**
	 * Crypter
	 */
	crypter_t *crypter;


	/**
	 * The encryption scheme
	 */
	enum {
		PKCS5_SCHEME_PBES1,
		PKCS5_SCHEME_PBES2,
		PKCS5_SCHEME_PKCS12,
	} scheme;

	/**
	 * Data used for individual schemes
	 */
	union {
		struct {
			/**
			 * Hash algorithm
			 */
			hash_algorithm_t hash;

			/**
			 * Hasher
			 */
			hasher_t *hasher;

		} pbes1;
		struct {
			/**
			 * PRF algorithm
			 */
			pseudo_random_function_t prf_alg;

			/**
			 * PRF
			 */
			prf_t * prf;

			/**
			 * IV
			 */
			chunk_t iv;

		} pbes2;
	} data;
};

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
typedef bool (*kdf_t)(private_pkcs5_t *this, chunk_t password, chunk_t key);

/**
 * Try to decrypt the given data with the given password using the given
 * key derivation function. keymat is where the kdf function writes the key
 * to, key and iv point to the actual keys and initialization vectors resp.
 */
static bool decrypt_generic(private_pkcs5_t *this, chunk_t password,
							chunk_t data, chunk_t *decrypted, kdf_t kdf,
							chunk_t keymat, chunk_t key, chunk_t iv)
{
	if (!kdf(this, password, keymat))
	{
		return FALSE;
	}
	if (!this->crypter->set_key(this->crypter, key) ||
		!this->crypter->decrypt(this->crypter, data, iv, decrypted))
	{
		memwipe(keymat.ptr, keymat.len);
		return FALSE;
	}
	memwipe(keymat.ptr, keymat.len);
	if (verify_padding(decrypted))
	{
		return TRUE;
	}
	chunk_free(decrypted);
	return FALSE;
}

/**
 * v * ceiling(len/v)
 */
#define PKCS12_LEN(len, v) (((len) + v-1) & ~(v-1))

/**
 * Copy src to dst as many times as possible
 */
static inline void pkcs12_copy_chunk(chunk_t dst, chunk_t src)
{
	size_t i;

	for (i = 0; i < dst.len; i++)
	{
		dst.ptr[i] = src.ptr[i % src.len];
	}
}

/**
 * Treat two chunks as integers in network order and add them together.
 * The result is stored in the first chunk, if the second chunk is longer or the
 * result overflows this is ignored.
 */
static void pkcs12_add_chunks(chunk_t a, chunk_t b)
{
	u_int16_t sum;
	u_int8_t rem = 0;
	ssize_t i, j;

	for (i = a.len - 1, j = b.len -1; i >= 0 && j >= 0; i--, j--)
	{
		sum = a.ptr[i] + b.ptr[j] + rem;
		a.ptr[i] = (u_char)sum;
		rem = sum >> 8;
	}
	for (; i >= 0 && rem; i--)
	{
		sum = a.ptr[i] + rem;
		a.ptr[i] = (u_char)sum;
		rem = sum >> 8;
	}
}

/**
 * Do the actual key derivation with the given password and id
 * id is 1 for encryption keys, 2 for IVs, 3 for MAC keys.
 */
static bool pkcs12_derive(private_pkcs5_t *this, chunk_t unicode,
						  char id, chunk_t result)
{
	chunk_t out = result, D, S, P = chunk_empty, I, Ai, B, Ij;
	hasher_t *hasher;
	size_t Slen, v, u;
	u_int64_t i;

	switch (this->data.pbes1.hash)
	{
		case HASH_MD2:
		case HASH_MD5:
		case HASH_SHA1:
		case HASH_SHA224:
		case HASH_SHA256:
			v = 64;
			break;
		case HASH_SHA384:
		case HASH_SHA512:
			v = 128;
			break;
		default:
			return FALSE;
	}
	hasher = this->data.pbes1.hasher;
	u = hasher->get_hash_size(hasher);

	D = chunk_alloca(v);
	memset(D.ptr, id, D.len);

	Slen = PKCS12_LEN(this->salt.len, v);
	I = chunk_alloca(Slen + PKCS12_LEN(unicode.len, v));
	S = chunk_create(I.ptr, Slen);
	P = chunk_create(I.ptr + Slen, I.len - Slen);
	pkcs12_copy_chunk(S, this->salt);
	pkcs12_copy_chunk(P, unicode);

	Ai = chunk_alloca(u);
	B = chunk_alloca(v);

	while (TRUE)
	{
		if (!hasher->get_hash(hasher, D, NULL) ||
			!hasher->get_hash(hasher, I, Ai.ptr))
		{
			return FALSE;
		}
		for (i = 1; i < this->iterations; i++)
		{
			if (!hasher->get_hash(hasher, Ai, Ai.ptr))
			{
				return FALSE;
			}
		}
		memcpy(out.ptr, Ai.ptr, min(out.len, Ai.len));
		out = chunk_skip(out, Ai.len);
		if (!out.len)
		{
			break;
		}
		pkcs12_copy_chunk(B, Ai);
		/* B = B+1 */
		pkcs12_add_chunks(B, chunk_from_chars(0x01));
		Ij = chunk_create(I.ptr, v);
		while (Ij.len)
		{	/* Ij = Ij + B + 1 */
			pkcs12_add_chunks(Ij, B);
			Ij = chunk_skip(Ij, v);
		}
	}
	return TRUE;
}

/**
 * KDF defined in PKCS#12
 */
static bool pkcs12_kdf(private_pkcs5_t *this, chunk_t password, chunk_t keymat)
{
	chunk_t unicode = chunk_empty, key, iv;
	int i;

	if (password.len)
	{	/* convert the password to UTF-16BE (without BOM) with 0 terminator */
		unicode = chunk_alloca(password.len * 2 + 2);
		for (i = 0; i < password.len; i++)
		{
			unicode.ptr[i * 2] = 0;
			unicode.ptr[i * 2 + 1] = password.ptr[i];
		}
		unicode.ptr[i * 2] = 0;
		unicode.ptr[i * 2 + 1] = 0;
	}

	key = chunk_create(keymat.ptr, this->keylen);
	iv = chunk_create(keymat.ptr + this->keylen, keymat.len - this->keylen);

	if (!pkcs12_derive(this, unicode, 1, key) ||
		!pkcs12_derive(this, unicode, 2, iv))
	{
		memwipe(unicode.ptr, unicode.len);
		return FALSE;
	}
	memwipe(unicode.ptr, unicode.len);
	return TRUE;
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
 * PBKDF2 key derivation function for PBES2, key must be allocated
 */
static bool pbkdf2(private_pkcs5_t *this, chunk_t password, chunk_t key)
{
	prf_t *prf;
	chunk_t keymat, block, seed;
	size_t blocks;
	u_int32_t i = 0;

	prf = this->data.pbes2.prf;

	if (!prf->set_key(prf, password))
	{
		return FALSE;
	}

	block.len = prf->get_block_size(prf);
	blocks = (key.len - 1) / block.len + 1;
	keymat = chunk_alloca(blocks * block.len);

	seed = chunk_cata("cc", this->salt, chunk_from_thing(i));

	for (; i < blocks; i++)
	{
		htoun32(seed.ptr + this->salt.len, i + 1);
		block.ptr = keymat.ptr + (i * block.len);
		if (!pbkdf2_f(block, prf, seed, this->iterations))
		{
			return FALSE;
		}
	}
	memcpy(key.ptr, keymat.ptr, key.len);
	return TRUE;
}

/**
 * PBKDF1 key derivation function for PBES1, key must be allocated
 */
static bool pbkdf1(private_pkcs5_t *this, chunk_t password, chunk_t key)
{
	hasher_t *hasher;
	chunk_t hash;
	u_int64_t i;

	hasher = this->data.pbes1.hasher;

	hash = chunk_alloca(hasher->get_hash_size(hasher));
	if (!hasher->get_hash(hasher, password, NULL) ||
		!hasher->get_hash(hasher, this->salt, hash.ptr))
	{
		return FALSE;
	}

	for (i = 1; i < this->iterations; i++)
	{
		if (!hasher->get_hash(hasher, hash, hash.ptr))
		{
			return FALSE;
		}
	}
	memcpy(key.ptr, hash.ptr, key.len);
	return TRUE;
}

static bool ensure_crypto_primitives(private_pkcs5_t *this, chunk_t data)
{
	if (!this->crypter)
	{
		this->crypter = lib->crypto->create_crypter(lib->crypto, this->encr,
													this->keylen);
		if (!this->crypter)
		{
			DBG1(DBG_ASN, "  %N encryption algorithm not available",
				 encryption_algorithm_names, this->encr);
			return FALSE;
		}
	}
	if (data.len % this->crypter->get_block_size(this->crypter))
	{
		DBG1(DBG_ASN, "  data size is not a multiple of block size");
		return FALSE;
	}
	switch (this->scheme)
	{
		case PKCS5_SCHEME_PBES1:
		case PKCS5_SCHEME_PKCS12:
		{
			if (!this->data.pbes1.hasher)
			{
				hasher_t *hasher;

				hasher = lib->crypto->create_hasher(lib->crypto,
													this->data.pbes1.hash);
				if (!hasher)
				{
					DBG1(DBG_ASN, "  %N hash algorithm not available",
						 hash_algorithm_names, this->data.pbes1.hash);
					return  FALSE;
				}
				if (hasher->get_hash_size(hasher) < this->keylen)
				{
					hasher->destroy(hasher);
					return FALSE;
				}
				this->data.pbes1.hasher = hasher;
			}
		}
		case PKCS5_SCHEME_PBES2:
		{
			if (!this->data.pbes2.prf)
			{
				prf_t *prf;

				prf = lib->crypto->create_prf(lib->crypto,
											  this->data.pbes2.prf_alg);
				if (!prf)
				{
					DBG1(DBG_ASN, "  %N prf algorithm not available",
						 pseudo_random_function_names,
						 this->data.pbes2.prf_alg);
					return FALSE;
				}
				this->data.pbes2.prf = prf;
			}
		}
	}
	return TRUE;
}

METHOD(pkcs5_t, decrypt, bool,
	private_pkcs5_t *this, chunk_t password, chunk_t data, chunk_t *decrypted)
{
	chunk_t keymat, key, iv;
	kdf_t kdf;

	if (!ensure_crypto_primitives(this, data) || !decrypted)
	{
		return FALSE;
	}
	kdf = pbkdf1;
	switch (this->scheme)
	{
		case PKCS5_SCHEME_PKCS12:
			kdf = pkcs12_kdf;
			/* fall-through */
		case PKCS5_SCHEME_PBES1:
			keymat = chunk_alloca(this->keylen +
								  this->crypter->get_iv_size(this->crypter));
			key = chunk_create(keymat.ptr, this->keylen);
			iv = chunk_create(keymat.ptr + this->keylen,
							  keymat.len - this->keylen);
			break;
		case PKCS5_SCHEME_PBES2:
			kdf = pbkdf2;
			keymat = chunk_alloca(this->keylen);
			key = keymat;
			iv = this->data.pbes2.iv;
			break;
		default:
			return FALSE;
	}
	return decrypt_generic(this, password, data, decrypted, kdf,
						   keymat, key, iv);
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
static bool parse_pbes1_params(private_pkcs5_t *this, chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success;

	parser = asn1_parser_create(pbeParameterObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PBEPARAM_SALT:
			{
				this->salt = chunk_clone(object);
				break;
			}
			case PBEPARAM_ITERATION_COUNT:
			{
				this->iterations = asn1_parse_integer_uint64(object);
				break;
			}
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	return success;
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
#define PBKDF2_KEYLENGTH			3
#define PBKDF2_PRF					5

/**
 * Parse a PBKDF2-params structure
 */
static bool parse_pbkdf2_params(private_pkcs5_t *this, chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success;

	parser = asn1_parser_create(pbkdf2ParamsObjects, blob);
	parser->set_top_level(parser, level0);

 	/* keylen is optional */
	this->keylen = 0;

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PBKDF2_SALT:
			{
				this->salt = chunk_clone(object);
				break;
			}
			case PBKDF2_ITERATION_COUNT:
			{
				this->iterations = asn1_parse_integer_uint64(object);
				break;
			}
			case PBKDF2_KEYLENGTH:
			{
				this->keylen = (size_t)asn1_parse_integer_uint64(object);
				break;
			}
			case PBKDF2_PRF:
			{	/* defaults to id-hmacWithSHA1, no other is currently defined */
				this->data.pbes2.prf_alg = PRF_HMAC_SHA1;
				break;
			}
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	return success;
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
static bool parse_pbes2_params(private_pkcs5_t *this, chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object, params;
	int objectID;
	bool success = FALSE;

	parser = asn1_parser_create(pbes2ParamsObjects, blob);
	parser->set_top_level(parser, level0);

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
				if (!parse_pbkdf2_params(this, params,
										 parser->get_level(parser) + 1))
				{
					goto end;
				}
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
				if (this->keylen <= 0)
				{	/* default key length for DES-EDE3-CBC-Pad */
					this->keylen = 24;
				}
				if (!asn1_parse_simple_object(&params, ASN1_OCTET_STRING,
									parser->get_level(parser) + 1, "IV"))
				{
					goto end;
				}
				this->encr = ENCR_3DES;
				this->data.pbes2.iv = chunk_clone(params);
				break;
			}
		}
	}
	success = parser->success(parser);
end:
	parser->destroy(parser);
	return success;
}

METHOD(pkcs5_t, destroy, void,
	private_pkcs5_t *this)
{
	DESTROY_IF(this->crypter);
	chunk_free(&this->salt);
	switch (this->scheme)
	{
		case PKCS5_SCHEME_PBES1:
		case PKCS5_SCHEME_PKCS12:
			DESTROY_IF(this->data.pbes1.hasher);
			break;
		case PKCS5_SCHEME_PBES2:
			DESTROY_IF(this->data.pbes2.prf);
			chunk_free(&this->data.pbes2.iv);
			break;
	}
	free(this);
}

/*
 * Described in header
 */
pkcs5_t *pkcs5_from_algorithmIdentifier(chunk_t blob, int level0)
{
	private_pkcs5_t *this;
	chunk_t params;
	int oid;

	INIT(this,
		.public = {
			.decrypt = _decrypt,
			.destroy = _destroy,
		},
		.scheme = PKCS5_SCHEME_PBES1,
		.keylen = 8,
	);

	oid = asn1_parse_algorithmIdentifier(blob, level0, &params);

	switch (oid)
	{
		case OID_PBE_MD5_DES_CBC:
			this->encr = ENCR_DES;
			this->data.pbes1.hash = HASH_MD5;
			break;
		case OID_PBE_SHA1_DES_CBC:
			this->encr = ENCR_DES;
			this->data.pbes1.hash = HASH_SHA1;
			break;
		case OID_PBE_SHA1_RC2_CBC_40:
			this->scheme = PKCS5_SCHEME_PKCS12;
			this->keylen = 5;
			this->encr = ENCR_RC2_CBC;
			this->data.pbes1.hash = HASH_SHA1;
			break;
		case OID_PBES2:
			this->scheme = PKCS5_SCHEME_PBES2;
			break;
		default:
			/* encryption scheme not supported */
			goto failure;
	}

	switch (this->scheme)
	{
		case PKCS5_SCHEME_PBES1:
		case PKCS5_SCHEME_PKCS12:
			if (!parse_pbes1_params(this, params, level0))
			{
				goto failure;
			}
			break;
		case PKCS5_SCHEME_PBES2:
			if (!parse_pbes2_params(this, params, level0))
			{
				goto failure;
			}
			break;
	}
	return &this->public;

failure:
	destroy(this);
	return NULL;
}
