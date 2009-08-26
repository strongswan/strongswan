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

#include "openssl_rsa_private_key.h"
#include "openssl_rsa_public_key.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

/**
 *  Public exponent to use for key generation.
 */
#define PUBLIC_EXPONENT 0x10001

typedef struct private_openssl_rsa_private_key_t private_openssl_rsa_private_key_t;

/**
 * Private data of a openssl_rsa_private_key_t object.
 */
struct private_openssl_rsa_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	openssl_rsa_private_key_t public;
	
	/**
	 * RSA object from OpenSSL
	 */
	RSA *rsa;
	
	/**
	 * TRUE if the key is from an OpenSSL ENGINE and might not be readable
	 */
	bool engine;
	
	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * Build an EMPSA PKCS1 signature described in PKCS#1
 */
static bool build_emsa_pkcs1_signature(private_openssl_rsa_private_key_t *this,
									   int type, chunk_t data, chunk_t *sig)
{
	bool success = FALSE;

	*sig = chunk_alloc(RSA_size(this->rsa));

	if (type == NID_undef)
	{
		if (RSA_private_encrypt(data.len, data.ptr, sig->ptr, this->rsa,
								RSA_PKCS1_PADDING) == sig->len)
		{
			success = TRUE;
		}
	}
	else
	{
		EVP_MD_CTX *ctx;
		EVP_PKEY *key;
		const EVP_MD *hasher;
		u_int len;
		
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
		if (!EVP_SignInit_ex(ctx, hasher, NULL))
		{
			goto error;
		}
		if (!EVP_SignUpdate(ctx, data.ptr, data.len))
		{
			goto error;
		}
		if (EVP_SignFinal(ctx, sig->ptr, &len, key))
		{
			success = TRUE;
		}
	
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
	if (!success)
	{
		free(sig->ptr);
	}
	return success;
}

/**
 * Implementation of openssl_rsa_private_key.get_type.
 */
static key_type_t get_type(private_openssl_rsa_private_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of openssl_rsa_private_key.sign.
 */
static bool sign(private_openssl_rsa_private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return build_emsa_pkcs1_signature(this, NID_undef, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return build_emsa_pkcs1_signature(this, NID_sha1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA224:
			return build_emsa_pkcs1_signature(this, NID_sha224, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return build_emsa_pkcs1_signature(this, NID_sha256, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return build_emsa_pkcs1_signature(this, NID_sha384, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return build_emsa_pkcs1_signature(this, NID_sha512, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return build_emsa_pkcs1_signature(this, NID_md5, data, signature);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of openssl_rsa_private_key.decrypt.
 */
static bool decrypt(private_openssl_rsa_private_key_t *this,
					chunk_t crypto, chunk_t *plain)
{
	DBG1("RSA private key decryption not implemented");
	return FALSE;
}

/**
 * Implementation of openssl_rsa_private_key.get_keysize.
 */
static size_t get_keysize(private_openssl_rsa_private_key_t *this)
{
	return RSA_size(this->rsa);
}

/**
 * Implementation of openssl_rsa_private_key.get_public_key.
 */
static public_key_t* get_public_key(private_openssl_rsa_private_key_t *this)
{
	chunk_t enc;
	public_key_t *key;
	u_char *p;
	
	enc = chunk_alloc(i2d_RSAPublicKey(this->rsa, NULL));
	p = enc.ptr;
	i2d_RSAPublicKey(this->rsa, &p);
	key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
							 BUILD_BLOB_ASN1_DER, enc, BUILD_END);
	free(enc.ptr);
	return key;
}

/**
 * Implementation of public_key_t.get_fingerprint.
 */
static bool get_fingerprint(private_openssl_rsa_private_key_t *this,
							key_encoding_type_t type, chunk_t *fingerprint)
{
	chunk_t enc;
	bool success;
	u_char *p;
	
	if (lib->encoding->get_cache(lib->encoding, type, this, fingerprint))
	{
		return TRUE;
	}
	enc = chunk_alloc(i2d_RSAPublicKey(this->rsa, NULL));
	p = enc.ptr;
	i2d_RSAPublicKey(this->rsa, &p);
	success = lib->encoding->encode(lib->encoding, type, this, fingerprint,
							KEY_PART_RSA_PUB_ASN1_DER, enc, KEY_PART_END);
	free(enc.ptr);
	return success;
}

/*
 * Implementation of public_key_t.get_encoding.
 */
static bool get_encoding(private_openssl_rsa_private_key_t *this,
						 key_encoding_type_t type, chunk_t *encoding)
{
	chunk_t enc;
	bool success;
	u_char *p;
	
	if (this->engine)
	{
		return FALSE;
	}
	enc = chunk_alloc(i2d_RSAPrivateKey(this->rsa, NULL));
	p = enc.ptr;
	i2d_RSAPrivateKey(this->rsa, &p);
	success = lib->encoding->encode(lib->encoding, type, NULL, encoding,
							KEY_PART_RSA_PRIV_ASN1_DER, enc, KEY_PART_END);
	free(enc.ptr);
	return success;
}

/**
 * Implementation of openssl_rsa_private_key.get_ref.
 */
static private_openssl_rsa_private_key_t* get_ref(private_openssl_rsa_private_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of openssl_rsa_private_key.destroy.
 */
static void destroy(private_openssl_rsa_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (this->rsa)
		{
			RSA_free(this->rsa);
		}
		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_openssl_rsa_private_key_t *create_empty(void)
{
	private_openssl_rsa_private_key_t *this = malloc_thing(private_openssl_rsa_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*) (private_key_t*))get_type;
	this->public.interface.sign = (bool (*) (private_key_t*, signature_scheme_t, chunk_t, chunk_t*))sign;
	this->public.interface.decrypt = (bool (*) (private_key_t*, chunk_t, chunk_t*))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t*))get_keysize;
	this->public.interface.get_public_key = (public_key_t* (*) (private_key_t*))get_public_key;
	this->public.interface.equals = private_key_equals;
	this->public.interface.belongs_to = private_key_belongs_to;
	this->public.interface.get_fingerprint = (bool(*)(private_key_t*, key_encoding_type_t type, chunk_t *fp))get_fingerprint;
	this->public.interface.get_encoding = (bool(*)(private_key_t*, key_encoding_type_t type, chunk_t *encoding))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*) (private_key_t*))get_ref;
	this->public.interface.destroy = (void (*) (private_key_t*))destroy;
	
	this->engine = FALSE;
	this->ref = 1;
	
	return this;
}

/**
 * Generate an RSA key of specified key size
 */
static openssl_rsa_private_key_t *generate(size_t key_size)
{
	private_openssl_rsa_private_key_t *this = create_empty();
	
	this->rsa = RSA_generate_key(key_size, PUBLIC_EXPONENT, NULL, NULL);
	
	return &this->public;
}

/**
 * load private key from an ASN1 encoded blob
 */
static openssl_rsa_private_key_t *load(chunk_t blob)
{
	u_char *p = blob.ptr;
	private_openssl_rsa_private_key_t *this = create_empty();
	
	this->rsa = d2i_RSAPrivateKey(NULL, (const u_char**)&p, blob.len);
	if (!this->rsa)
	{
		destroy(this);
		return NULL;
	}
	if (!RSA_check_key(this->rsa))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * load private key from a smart card
 */
static openssl_rsa_private_key_t *load_from_smartcard(char *keyid, char *pin)
{
	private_openssl_rsa_private_key_t *this = NULL;
	EVP_PKEY *key;
	char *engine_id = lib->settings->get_str(lib->settings,
								"library.plugins.openssl.engine_id", "pkcs11");
	
	ENGINE *engine = ENGINE_by_id(engine_id);
	if (!engine)
	{
		DBG1("engine '%s' is not available", engine_id);
		return NULL;
	}
	
	if (!ENGINE_init(engine))
	{
		DBG1("failed to initialize engine '%s'", engine_id);
		goto error;
	}
	
	if (!ENGINE_ctrl_cmd_string(engine, "PIN", pin, 0))
	{
		DBG1("failed to set PIN on engine '%s'", engine_id);
		goto error;
	}
	
	key = ENGINE_load_private_key(engine, keyid, NULL, NULL);
	
	if (!key)
	{
		DBG1("failed to load private key with ID '%s' from engine '%s'", keyid,
				engine_id);
		goto error;
	}
	ENGINE_free(engine);
	
	this = create_empty();
	this->rsa = EVP_PKEY_get1_RSA(key);
	this->engine = TRUE;
	
	return &this->public;
	
error:
	ENGINE_free(engine);
	return NULL;
}

typedef struct private_builder_t private_builder_t;

/**
 * Builder implementation for key loading/generation
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded/generated private key */
	openssl_rsa_private_key_t *key;
	/** temporary stored smartcard key ID */
	char *keyid;
	/** temporary stored smartcard pin */
	char *pin;
};

/**
 * Implementation of builder_t.build
 */
static openssl_rsa_private_key_t *build(private_builder_t *this)
{
	openssl_rsa_private_key_t *key = this->key;
	
	if (this->keyid && this->pin)
	{
		key = load_from_smartcard(this->keyid, this->pin);
	}
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
			case BUILD_KEY_SIZE:
			{
				va_start(args, part);
				this->key = generate(va_arg(args, u_int));
				va_end(args);
				return;
			}
			case BUILD_SMARTCARD_KEYID:
			{
				va_start(args, part);
				this->keyid = va_arg(args, char*);
				va_end(args);
				return;
			}
			case BUILD_SMARTCARD_PIN:
			{
				va_start(args, part);
				this->pin = va_arg(args, char*);
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_openssl_rsa_private_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *openssl_rsa_private_key_builder(key_type_t type)
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
	this->keyid = NULL;
	this->pin = NULL;
	
	return &this->public;
}

