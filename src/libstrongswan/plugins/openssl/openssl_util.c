/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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

#include "openssl_util.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

/**
 * Described in header.
 */
bool openssl_hash_chunk(int hash_type, chunk_t data, chunk_t *hash)
{
	EVP_MD_CTX *ctx;
	bool ret = FALSE;
	const EVP_MD *hasher = EVP_get_digestbynid(hash_type);
	if (!hasher)
	{
		return FALSE;
	}
	
	ctx = EVP_MD_CTX_create();	
	if (!ctx)
	{
		goto error;
	}
	
	if (!EVP_DigestInit_ex(ctx, hasher, NULL))
	{
		goto error;
	}
	
	if (!EVP_DigestUpdate(ctx, data.ptr, data.len))
	{
		goto error;
	}
	
	*hash = chunk_alloc(hasher->md_size);
	if (!EVP_DigestFinal_ex(ctx, hash->ptr, NULL))
	{
		chunk_free(hash);
		goto error;
	}
	
	ret = TRUE;
error:
	if (ctx)
	{
		EVP_MD_CTX_destroy(ctx);
	}
	return ret;
}

/**
 * Described in header.
 */
bool openssl_bn_cat(int len, BIGNUM *a, BIGNUM *b, chunk_t *chunk)
{
	int offset;
	
	chunk->len = len + (b ? len : 0);
	chunk->ptr = malloc(chunk->len);
	memset(chunk->ptr, 0, chunk->len);
	
	/* convert a */
	offset = len - BN_num_bytes(a);
	if (!BN_bn2bin(a, chunk->ptr + offset))
	{
		goto error;
	}
	
	/* optionally convert and concatenate b */
	if (b)
	{
		offset = len - BN_num_bytes(b);
		if (!BN_bn2bin(b, chunk->ptr + len + offset))
		{
			goto error;
		}
	}	
	
	return TRUE;
error:
	chunk_free(chunk);
	return FALSE;
}


/**
 * Described in header.
 */
bool openssl_bn_split(chunk_t chunk, BIGNUM *a, BIGNUM *b)
{
	int len;
	
	if ((chunk.len % 2) != 0)
	{
		return FALSE;
	}
	
	len = chunk.len / 2;
	
	if (!BN_bin2bn(chunk.ptr, len, a) ||
		!BN_bin2bn(chunk.ptr + len, len, b))
	{
		return FALSE;
	}
	
	return TRUE;
}

/**
 * wrap publicKey in subjectPublicKeyInfo
 */
static chunk_t build_info(chunk_t key)
{
	X509_PUBKEY *pubkey;
	chunk_t enc;
	u_char *p;
	
	pubkey = X509_PUBKEY_new();
	ASN1_OBJECT_free(pubkey->algor->algorithm);
	pubkey->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);

	if (pubkey->algor->parameter == NULL ||
		pubkey->algor->parameter->type != V_ASN1_NULL)
	{
		ASN1_TYPE_free(pubkey->algor->parameter);
		pubkey->algor->parameter = ASN1_TYPE_new();
		pubkey->algor->parameter->type = V_ASN1_NULL;
	}
	M_ASN1_BIT_STRING_set(pubkey->public_key, key.ptr, key.len);
	
	enc = chunk_alloc(i2d_X509_PUBKEY(pubkey, NULL));
	p = enc.ptr;
	i2d_X509_PUBKEY(pubkey, &p);
	X509_PUBKEY_free(pubkey);
	
	return enc;
}

/**
 * Build fingerprints of a private/public RSA key.
 */
static bool build_fingerprint(chunk_t key, key_encoding_type_t type,
							  chunk_t *fingerprint)
{
	hasher_t *hasher;
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1("SHA1 hash algorithm not supported, fingerprinting failed");
		return FALSE;
	}
	if (type == KEY_ID_PUBKEY_INFO_SHA1)
	{
		chunk_t enc;
		
		enc = build_info(key);
		hasher->allocate_hash(hasher, enc, fingerprint);
		chunk_free(&enc);
	}
	else
	{
		hasher->allocate_hash(hasher, key, fingerprint);
	}
	hasher->destroy(hasher);
	return TRUE;
}

/**
 * See header.
 */
bool openssl_encode(key_encoding_type_t type, chunk_t *encoding, va_list args)
{
	chunk_t key;
	
	switch (type)
	{
		case KEY_PUB_ASN1_DER:
			/* this encoding is currently not supported for ECDSA keys */
			if (key_encoding_args(args, KEY_PART_RSA_PUB_ASN1_DER, &key,
								  KEY_PART_END))
			{
				*encoding = chunk_clone(key);
				return TRUE;
			}
			return FALSE;
		case KEY_PUB_SPKI_ASN1_DER:
			/* key encoding, wrapped in a subjectPublicKeyInfo field */
			if (key_encoding_args(args, KEY_PART_RSA_PUB_ASN1_DER, &key,
								  KEY_PART_END))
			{
				*encoding = build_info(key);
				return TRUE;
			}
			else if (key_encoding_args(args, KEY_PART_ECDSA_PUB_ASN1_DER, &key,
									   KEY_PART_END))
			{
				/* ECDSA keys are already wrapped in the publickeyInfo field,
				 * they are incomplete without */
				*encoding = chunk_clone(key);
				return TRUE;
			}
			return FALSE;
		case KEY_PRIV_ASN1_DER:
			if (key_encoding_args(args, KEY_PART_RSA_PRIV_ASN1_DER, &key,
								  KEY_PART_END) ||
				key_encoding_args(args, KEY_PART_ECDSA_PRIV_ASN1_DER, &key,
								  KEY_PART_END))
			{
				*encoding = chunk_clone(key);
				return TRUE;
			}
			return FALSE;
		case KEY_ID_PUBKEY_SHA1:
		case KEY_ID_PUBKEY_INFO_SHA1:
			if (key_encoding_args(args, KEY_PART_RSA_PUB_ASN1_DER, &key,
								  KEY_PART_END))
			{
				return build_fingerprint(key, type, encoding);
			}
			else if (key_encoding_args(args, KEY_PART_ECDSA_PUB_ASN1_DER, &key,
									   KEY_PART_END))
			{
				/* for ECDSA the two keyids are currently the same */
				return build_fingerprint(key, KEY_ID_PUBKEY_SHA1, encoding);
			}
			return FALSE;
		default:
			return FALSE;
	}
}

