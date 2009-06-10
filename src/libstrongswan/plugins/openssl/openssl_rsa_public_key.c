/*
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
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	identification_t *keyid_info;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKey object
	 */
	identification_t *keyid;
	
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
		case SIGN_DEFAULT:
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_emsa_pkcs1_signature(this, NID_undef, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_emsa_pkcs1_signature(this, NID_sha1, data, signature);
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
static bool encrypt_(private_openssl_rsa_public_key_t *this, chunk_t crypto, chunk_t *plain)
{
	DBG1("RSA public key encryption not implemented");
	return FALSE;
}

/**
 * Implementation of public_key_t.equals.
 */
static bool equals(private_openssl_rsa_public_key_t *this, public_key_t *other)
{
	identification_t *keyid;

	if (&this->public.interface == other)
	{
		return TRUE;
	}
	if (other->get_type(other) != KEY_RSA)
	{
		return FALSE;
	}
	keyid = other->get_id(other, ID_PUBKEY_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid))
	{
		return TRUE;
	}
	keyid = other->get_id(other, ID_PUBKEY_INFO_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid_info))
	{
		return TRUE;
	}
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
 * Implementation of public_key_t.get_id.
 */
static identification_t *get_id(private_openssl_rsa_public_key_t *this,
								id_type_t type)
{
	switch (type)
	{
		case ID_PUBKEY_INFO_SHA1:
			return this->keyid_info;
		case ID_PUBKEY_SHA1:
			return this->keyid;
		default:
			return NULL;
	}
}

/**
 * Encodes the public key
 */ 
static chunk_t get_encoding_raw(RSA *rsa)
{
	chunk_t enc = chunk_alloc(i2d_RSAPublicKey(rsa, NULL));
	u_char *p = enc.ptr;
	i2d_RSAPublicKey(rsa, &p);
	return enc;
}

/**
 * Encodes the public key with the algorithm used
 */
static chunk_t get_encoding_with_algo(RSA *rsa)
{
	u_char *p;
	chunk_t enc;
	X509_PUBKEY *pubkey = X509_PUBKEY_new();
	
	ASN1_OBJECT_free(pubkey->algor->algorithm);
	pubkey->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
	
	if (pubkey->algor->parameter == NULL ||
		pubkey->algor->parameter->type != V_ASN1_NULL)
	{
		ASN1_TYPE_free(pubkey->algor->parameter);
		pubkey->algor->parameter = ASN1_TYPE_new();
		pubkey->algor->parameter->type = V_ASN1_NULL;
	}
	
	enc = get_encoding_raw(rsa);
	M_ASN1_BIT_STRING_set(pubkey->public_key, enc.ptr, enc.len);
	chunk_free(&enc);
	
	enc = chunk_alloc(i2d_X509_PUBKEY(pubkey, NULL));
	p = enc.ptr;
	i2d_X509_PUBKEY(pubkey, &p);
	X509_PUBKEY_free(pubkey);
	return enc;
}

/*
 * Implementation of public_key_t.get_encoding.
 */
static chunk_t get_encoding(private_openssl_rsa_public_key_t *this)
{
	return get_encoding_raw(this->rsa);
}

/**
 * Implementation of public_key_t.get_ref.
 */
static private_openssl_rsa_public_key_t* get_ref(private_openssl_rsa_public_key_t *this)
{
	ref_get(&this->ref);
	return this;
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
			RSA_free(this->rsa);
		}
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_openssl_rsa_public_key_t *openssl_rsa_public_key_create_empty()
{
	private_openssl_rsa_public_key_t *this = malloc_thing(private_openssl_rsa_public_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(public_key_t *this))get_type;
	this->public.interface.verify = (bool (*)(public_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t signature))verify;
	this->public.interface.encrypt = (bool (*)(public_key_t *this, chunk_t crypto, chunk_t *plain))encrypt_;
	this->public.interface.equals = (bool (*) (public_key_t*, public_key_t*))equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (public_key_t *this,id_type_t))get_id;
	this->public.interface.get_encoding = (chunk_t(*)(public_key_t*))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*)(public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(public_key_t *this))destroy;
	
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Build the RSA key identifier from n and e using SHA1 hashed publicKey(Info).
 * Also used in openssl_rsa_private_key.c.
 */
bool openssl_rsa_public_key_build_id(RSA *rsa, identification_t **keyid,
								 identification_t **keyid_info)
{
	chunk_t publicKeyInfo, publicKey, hash;
	hasher_t *hasher;
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		DBG1("SHA1 hash algorithm not supported, unable to use RSA");
		return FALSE;
	}
	
	publicKey = get_encoding_raw(rsa);
	
	hasher->allocate_hash(hasher, publicKey, &hash);
	*keyid = identification_create_from_encoding(ID_PUBKEY_SHA1, hash);
	chunk_free(&hash);
	
	publicKeyInfo = get_encoding_with_algo(rsa);
	
	hasher->allocate_hash(hasher, publicKeyInfo, &hash);
	*keyid_info = identification_create_from_encoding(ID_PUBKEY_INFO_SHA1, hash);
	chunk_free(&hash);
	
	hasher->destroy(hasher);
	chunk_free(&publicKeyInfo);
	chunk_free(&publicKey);
	
	return TRUE;
}

/**
 * Create a public key from BIGNUM values, used in openssl_rsa_private_key.c
 */
openssl_rsa_public_key_t *openssl_rsa_public_key_create_from_n_e(BIGNUM *n, BIGNUM *e)
{
	private_openssl_rsa_public_key_t *this = openssl_rsa_public_key_create_empty();
	
	this->rsa = RSA_new();
	this->rsa->n = BN_dup(n);
	this->rsa->e = BN_dup(e);
	
	if (!openssl_rsa_public_key_build_id(this->rsa, &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * Load a public key from an ASN1 encoded blob
 */
static openssl_rsa_public_key_t *load(chunk_t blob)
{
	u_char *p = blob.ptr;
	private_openssl_rsa_public_key_t *this = openssl_rsa_public_key_create_empty();

	this->rsa = d2i_RSAPublicKey(NULL, (const u_char**)&p, blob.len);
	
	chunk_clear(&blob);

	if (!this->rsa)
	{
		destroy(this);
		return NULL;
	}

	if (!openssl_rsa_public_key_build_id(this->rsa, &this->keyid, &this->keyid_info))
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
		chunk_t chunk;
	
		switch (part)
		{
			case BUILD_BLOB_ASN1_DER:
			{
				va_start(args, part);
				chunk = va_arg(args, chunk_t);
				this->key = load(chunk_clone(chunk));
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

