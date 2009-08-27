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

#include "openssl_rsa_public_key.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

typedef struct private_openssl_rsa_public_key_t private_openssl_rsa_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_openssl_rsa_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	openssl_rsa_public_key_t public;
	
	/**
	 * RSA object from OpenSSL
	 */
	RSA *rsa;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Verification of an EMPSA PKCS1 signature described in PKCS#1
 */
static bool verify_emsa_pkcs1_signature(private_openssl_rsa_public_key_t *this,
										int type, chunk_t data, chunk_t signature)
{
	bool valid = FALSE;
	int rsa_size = RSA_size(this->rsa);

	/* OpenSSL expects a signature of exactly RSA size (no leading 0x00) */
	if (signature.len > rsa_size)
	{
		signature = chunk_skip(signature, signature.len - rsa_size);
	}

	if (type == NID_undef)
	{
		chunk_t hash = chunk_alloc(rsa_size);

		hash.len = RSA_public_decrypt(signature.len, signature.ptr, hash.ptr,
									  this->rsa, RSA_PKCS1_PADDING);
		valid = chunk_equals(data, hash);
		free(hash.ptr);
	}
	else
	{
		EVP_MD_CTX *ctx;
		EVP_PKEY *key;
		const EVP_MD *hasher;

		hasher = EVP_get_digestbynid(type);
		if (!hasher)
		{
			return FALSE;
		}

		ctx = EVP_MD_CTX_create();
		key = EVP_PKEY_new();

		if (!ctx || !key)
		{
			goto error;
		}
		if (!EVP_PKEY_set1_RSA(key, this->rsa))
		{
			goto error;
		}
		if (!EVP_VerifyInit_ex(ctx, hasher, NULL))
		{
			goto error;
		}
		if (!EVP_VerifyUpdate(ctx, data.ptr, data.len))
		{
			goto error;
		}
		valid = (EVP_VerifyFinal(ctx, signature.ptr, signature.len, key) == 1);
	
error:
		if (key)
		{
			EVP_PKEY_free(key);
		}
		if (ctx)
		{
			EVP_MD_CTX_destroy(ctx);
		}
	}
	return valid;
}

/**
 * Implementation of public_key_t.get_type.
 */
static key_type_t get_type(private_openssl_rsa_public_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of public_key_t.verify.
 */
static bool verify(private_openssl_rsa_public_key_t *this, signature_scheme_t scheme, 
				   chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_emsa_pkcs1_signature(this, NID_undef, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_emsa_pkcs1_signature(this, NID_sha1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA224:
			return verify_emsa_pkcs1_signature(this, NID_sha224, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return verify_emsa_pkcs1_signature(this, NID_sha256, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return verify_emsa_pkcs1_signature(this, NID_sha384, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return verify_emsa_pkcs1_signature(this, NID_sha512, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return verify_emsa_pkcs1_signature(this, NID_md5, data, signature);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static bool encrypt_(private_openssl_rsa_public_key_t *this,
					 chunk_t crypto, chunk_t *plain)
{
	DBG1("RSA public key encryption not implemented");
	return FALSE;
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static size_t get_keysize(private_openssl_rsa_public_key_t *this)
{
	return RSA_size(this->rsa);
}

/**
 * Calculate fingerprint from a RSA key, also used in rsa private key.
 */
bool openssl_rsa_fingerprint(RSA *rsa, key_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;
	u_char *p;
	
	if (lib->encoding->get_cache(lib->encoding, type, rsa, fp))
	{
		return TRUE;
	}
	switch (type)
	{
		case KEY_ID_PUBKEY_SHA1:
			key = chunk_alloc(i2d_RSAPublicKey(rsa, NULL));
			p = key.ptr;
			i2d_RSAPublicKey(rsa, &p);
			break;
		case KEY_ID_PUBKEY_INFO_SHA1:
			key = chunk_alloc(i2d_RSA_PUBKEY(rsa, NULL));
			p = key.ptr;
			i2d_RSA_PUBKEY(rsa, &p);
			break;
		default:
			return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1("SHA1 hash algorithm not supported, fingerprinting failed");
		free(key.ptr);
		return FALSE;
	}
	hasher->allocate_hash(hasher, key, fp);
	hasher->destroy(hasher);
	lib->encoding->cache(lib->encoding, type, rsa, *fp);
	return TRUE;
}

/**
 * Implementation of public_key_t.get_fingerprint.
 */
static bool get_fingerprint(private_openssl_rsa_public_key_t *this,
							key_encoding_type_t type, chunk_t *fingerprint)
{
	return openssl_rsa_fingerprint(this->rsa, type, fingerprint);
}

/*
 * Implementation of public_key_t.get_encoding.
 */
static bool get_encoding(private_openssl_rsa_public_key_t *this,
						 key_encoding_type_t type, chunk_t *encoding)
{
	u_char *p;
	
	switch (type)
	{
		case KEY_PUB_SPKI_ASN1_DER:
		{
			*encoding = chunk_alloc(i2d_RSA_PUBKEY(this->rsa, NULL));
			p = encoding->ptr;
			i2d_RSA_PUBKEY(this->rsa, &p);
			return TRUE;
		}
		case KEY_PUB_ASN1_DER:
		{
			*encoding = chunk_alloc(i2d_RSAPublicKey(this->rsa, NULL));
			p = encoding->ptr;
			i2d_RSAPublicKey(this->rsa, &p);
			return TRUE;
		}
		default:
			return FALSE;
	}
}

/**
 * Implementation of public_key_t.get_ref.
 */
static public_key_t* get_ref(private_openssl_rsa_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
}

/**
 * Implementation of openssl_rsa_public_key.destroy.
 */
static void destroy(private_openssl_rsa_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (this->rsa)
		{
			lib->encoding->clear_cache(lib->encoding, this->rsa);
			RSA_free(this->rsa);
		}
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_openssl_rsa_public_key_t *create_empty()
{
	private_openssl_rsa_public_key_t *this = malloc_thing(private_openssl_rsa_public_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(public_key_t *this))get_type;
	this->public.interface.verify = (bool (*)(public_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t signature))verify;
	this->public.interface.encrypt = (bool (*)(public_key_t *this, chunk_t crypto, chunk_t *plain))encrypt_;
	this->public.interface.equals = public_key_equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t *this))get_keysize;
	this->public.interface.get_fingerprint = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *fp))get_fingerprint;
	this->public.interface.get_encoding = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *encoding))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*)(public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(public_key_t *this))destroy;
	
	this->rsa = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Load a public key from an ASN1 encoded blob
 */
static openssl_rsa_public_key_t *load(chunk_t blob)
{
	u_char *p = blob.ptr;
	private_openssl_rsa_public_key_t *this = create_empty();
	
	this->rsa = d2i_RSAPublicKey(NULL, (const u_char**)&p, blob.len);
	if (!this->rsa)
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

typedef struct private_builder_t private_builder_t;

/**
 * Builder implementation for key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded public key */
	openssl_rsa_public_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static openssl_rsa_public_key_t *build(private_builder_t *this)
{
	openssl_rsa_public_key_t *key = this->key;
	
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
				this->key = load(va_arg(args, chunk_t));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_openssl_rsa_public_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *openssl_rsa_public_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->key = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

