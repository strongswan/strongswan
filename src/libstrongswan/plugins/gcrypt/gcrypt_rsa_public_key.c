/*
 * Copyright (C) 2005-2009 Martin Willi
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
 
#include <gcrypt.h>

#include "gcrypt_rsa_public_key.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/pem.h>
#include <crypto/hashers/hasher.h>

typedef struct private_gcrypt_rsa_public_key_t private_gcrypt_rsa_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_gcrypt_rsa_public_key_t {
	
	/**
	 * Public interface for this signer.
	 */
	gcrypt_rsa_public_key_t public;
	
	/**
	 * gcrypt S-expression representing an public RSA key
	 */
	gcry_sexp_t key;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKey object
	 */
	identification_t* keyid;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	identification_t* keyid_info;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Implemented in gcrypt_rsa_private_key.c
 */
chunk_t gcrypt_rsa_find_token(gcry_sexp_t sexp, char *name);
bool gcrypt_rsa_build_keyids(gcry_sexp_t key, identification_t **keyid,
							 identification_t **keyid_info);

/**
 * verification of a padded PKCS1 signature without an OID
 */
static bool verify_raw(private_gcrypt_rsa_public_key_t *this,
						 chunk_t data, chunk_t signature)
{
	gcry_sexp_t in, sig;
	gcry_error_t err;
	chunk_t em;
	size_t k;
	
	/* EM = 0x00 || 0x01 || PS || 0x00 || T
	 * PS = 0xFF padding, with length to fill em
	 * T  = data
	 */
	k = gcry_pk_get_nbits(this->key) / 8;
	if (data.len > k - 3)
	{
		return FALSE;
	}
	em = chunk_alloc(k);
	memset(em.ptr, 0xFF, em.len);
	em.ptr[0] = 0x00;
	em.ptr[1] = 0x01;
	em.ptr[em.len - data.len - 1] = 0x00;
	memcpy(em.ptr + em.len - data.len, data.ptr, data.len);
	
	err = gcry_sexp_build(&in, NULL, "(data(flags raw)(value %b))",
						  em.len, em.ptr);
	chunk_free(&em);
	if (err)
	{
		DBG1("building data S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	err = gcry_sexp_build(&sig, NULL, "(sig-val(rsa(s %b)))",
						  signature.len, signature.ptr);
	if (err)
	{
		DBG1("building signature S-expression failed: %s", gpg_strerror(err));
		gcry_sexp_release(in);
		return FALSE;
	}
	err = gcry_pk_verify(sig, in, this->key);
	gcry_sexp_release(in);
	gcry_sexp_release(sig);
	if (err)
	{
		DBG1("RSA signature verification failed: %s", gpg_strerror(err));
		return FALSE;
	}
	return TRUE;
}

/**
 * Verification of an EMSA PKCS1 signature described in PKCS#1
 */
static bool verify_pkcs1(private_gcrypt_rsa_public_key_t *this,
						 hash_algorithm_t algorithm, char *hash_name,
						 chunk_t data, chunk_t signature)
{
	hasher_t *hasher;
	chunk_t hash;
	gcry_error_t err;
	gcry_sexp_t in, sig;
	
	hasher = lib->crypto->create_hasher(lib->crypto, algorithm);
	if (!hasher)
	{
		return FALSE;
	}
	hasher->allocate_hash(hasher, data, &hash);
	hasher->destroy(hasher);
	
	err = gcry_sexp_build(&in, NULL, "(data(flags pkcs1)(hash %s %b))",
						  hash_name, hash.len, hash.ptr);
	chunk_free(&hash);
	if (err)
	{
		DBG1("building data S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	
	err = gcry_sexp_build(&sig, NULL, "(sig-val(rsa(s %b)))",
						  signature.len, signature.ptr);
	if (err)
	{
		DBG1("building signature S-expression failed: %s", gpg_strerror(err));
		gcry_sexp_release(in);
		return FALSE;
	}
	err = gcry_pk_verify(sig, in, this->key);
	gcry_sexp_release(in);
	gcry_sexp_release(sig);
	if (err)
	{
		DBG1("RSA signature verification failed: %s", gpg_strerror(err));
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of public_key_t.get_type.
 */
static key_type_t get_type(private_gcrypt_rsa_public_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of public_key_t.verify.
 */
static bool verify(private_gcrypt_rsa_public_key_t *this,
				   signature_scheme_t scheme, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_raw(this, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return verify_pkcs1(this, HASH_MD5, "md5", data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_pkcs1(this, HASH_SHA1, "sha1", data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return verify_pkcs1(this, HASH_SHA256, "sha256", data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return verify_pkcs1(this, HASH_SHA384, "sha384", data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return verify_pkcs1(this, HASH_SHA512, "sha512", data, signature);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of public_key_t.encrypt.
 */
static bool encrypt_(private_gcrypt_rsa_public_key_t *this, chunk_t plain,
					 chunk_t *encrypted)
{
	gcry_sexp_t in, out;
	gcry_error_t err;
	
	/* "pkcs1" uses PKCS 1.5 (section 8.1) block type 2 encryption:
	 * 00 | 02 | RANDOM | 00 | DATA */
	err = gcry_sexp_build(&in, NULL, "(data(flags pkcs1)(value %b))",
						  plain.len, plain.ptr);
	if (err)
	{
		DBG1("building encryption S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	err = gcry_pk_encrypt(&out, in, this->key);
	gcry_sexp_release(in);
	if (err)
	{
		DBG1("encrypting data using pkcs1 failed: %s", gpg_strerror(err));
		return FALSE;
	}
	*encrypted = gcrypt_rsa_find_token(out, "a");
	gcry_sexp_release(out);
	return !!encrypted->len;
}

/**
 * Implementation of gcrypt_rsa_public_key.equals.
 */
static bool equals(private_gcrypt_rsa_public_key_t *this, public_key_t *other)
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
static size_t get_keysize(private_gcrypt_rsa_public_key_t *this)
{
	return gcry_pk_get_nbits(this->key) / 8;
}

/**
 * Implementation of public_key_t.get_id.
 */
static identification_t *get_id(private_gcrypt_rsa_public_key_t *this,
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

/*
 * Implementation of public_key_t.get_encoding.
 */
static chunk_t get_encoding(private_gcrypt_rsa_public_key_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
			asn1_integer("m", gcrypt_rsa_find_token(this->key, "n")),
			asn1_integer("m", gcrypt_rsa_find_token(this->key, "e")));
}

/**
 * Implementation of public_key_t.get_ref.
 */
static public_key_t* get_ref(private_gcrypt_rsa_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
}

/**
 * Implementation of gcrypt_rsa_public_key.destroy.
 */
static void destroy(private_gcrypt_rsa_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		gcry_sexp_release(this->key);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_gcrypt_rsa_public_key_t *gcrypt_rsa_public_key_create_empty()
{
	private_gcrypt_rsa_public_key_t *this = malloc_thing(private_gcrypt_rsa_public_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(public_key_t *this))get_type;
	this->public.interface.verify = (bool (*)(public_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t signature))verify;
	this->public.interface.encrypt = (bool (*)(public_key_t *this, chunk_t crypto, chunk_t *plain))encrypt_;
	this->public.interface.equals = (bool (*) (public_key_t*, public_key_t*))equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (public_key_t *this,id_type_t))get_id;
	this->public.interface.get_encoding = (chunk_t(*)(public_key_t*))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*)(public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(public_key_t *this))destroy;
	
	this->key = NULL;
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Create a public key from a S-expression, used in gcrypt_rsa_private_key
 */
public_key_t *gcrypt_rsa_public_key_create_from_sexp(gcry_sexp_t key)
{
	private_gcrypt_rsa_public_key_t *this;
	gcry_error_t err;
	chunk_t n, e;
	
	this = gcrypt_rsa_public_key_create_empty();
	n = gcrypt_rsa_find_token(key, "n");
	e = gcrypt_rsa_find_token(key, "e");
	
	err = gcry_sexp_build(&this->key, NULL, "(public-key(rsa(n %b)(e %b)))",
						  n.len, n.ptr, e.len, e.ptr);
	chunk_free(&n);
	chunk_free(&e);
	if (err)
	{
		DBG1("loading public key failed: %s", gpg_strerror(err));
		free(this);
		return NULL;
	}
	if (!gcrypt_rsa_build_keyids(this->key, &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public.interface;
}

/**
 * ASN.1 definition of RSApublicKey
 */
static const asn1Object_t pubkeyObjects[] = {
	{ 0, "RSAPublicKey",		ASN1_SEQUENCE,	ASN1_OBJ  }, /*  0 */
	{ 1,   "modulus",			ASN1_INTEGER,	ASN1_BODY }, /*  1 */
	{ 1,   "publicExponent",	ASN1_INTEGER,	ASN1_BODY }, /*  2 */
	{ 0, "exit",				ASN1_EOC,		ASN1_EXIT }
};
#define PUB_KEY_RSA_PUBLIC_KEY		0
#define PUB_KEY_MODULUS				1
#define PUB_KEY_EXPONENT			2

/**
 * Load a public key from an ASN1 encoded blob
 */
static gcrypt_rsa_public_key_t *load(chunk_t blob)
{
	private_gcrypt_rsa_public_key_t *this;
	asn1_parser_t *parser;
	chunk_t object, n, e;
	int objectID;
	bool success = FALSE;
	gcry_error_t err;
	
	parser = asn1_parser_create(pubkeyObjects, blob);
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PUB_KEY_MODULUS:
				n = object;
				break;
			case PUB_KEY_EXPONENT:
				e = object;
				break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	
	if (!success)
	{
		return NULL;
	}
	
	this = gcrypt_rsa_public_key_create_empty();
	err = gcry_sexp_build(&this->key, NULL, "(public-key(rsa(n %b)(e %b)))",
						  n.len, n.ptr, e.len, e.ptr);
	if (err)
	{
		DBG1("loading public key failed: %s", gpg_strerror(err));
		free(this);
		return NULL;
	}
	if (!gcrypt_rsa_build_keyids(this->key, &this->keyid, &this->keyid_info))
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
	gcrypt_rsa_public_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static gcrypt_rsa_public_key_t *build(private_builder_t *this)
{
	gcrypt_rsa_public_key_t *key = this->key;
	
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
		destroy((private_gcrypt_rsa_public_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *gcrypt_rsa_public_key_builder(key_type_t type)
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

