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
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Implemented in gcrypt_rsa_private_key.c
 */
chunk_t gcrypt_rsa_find_token(gcry_sexp_t sexp, char *name, gcry_sexp_t key);

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
		case SIGN_RSA_EMSA_PKCS1_SHA224:
			return verify_pkcs1(this, HASH_SHA224, "sha224", data, signature);
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
	*encrypted = gcrypt_rsa_find_token(out, "a", this->key);
	gcry_sexp_release(out);
	return !!encrypted->len;
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static size_t get_keysize(private_gcrypt_rsa_public_key_t *this)
{
	return gcry_pk_get_nbits(this->key) / 8;
}

/**
 * Implementation of private_key_t.get_encoding
 */
static bool get_encoding(private_gcrypt_rsa_public_key_t *this,
						 key_encoding_type_t type, chunk_t *encoding)
{
	chunk_t n, e;
	bool success;

	n = gcrypt_rsa_find_token(this->key, "n", NULL);
	e = gcrypt_rsa_find_token(this->key, "e", NULL);
	success = lib->encoding->encode(lib->encoding, type, NULL, encoding,
							KEY_PART_RSA_MODULUS, n, KEY_PART_RSA_PUB_EXP, e,
							KEY_PART_END);
	chunk_free(&n);
	chunk_free(&e);

	return success;
}

/**
 * Implementation of private_key_t.get_fingerprint
 */
static bool get_fingerprint(private_gcrypt_rsa_public_key_t *this,
							key_encoding_type_t type, chunk_t *fp)
{
	chunk_t n, e;
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	n = gcrypt_rsa_find_token(this->key, "n", NULL);
	e = gcrypt_rsa_find_token(this->key, "e", NULL);

	success = lib->encoding->encode(lib->encoding,
								type, this, fp, KEY_PART_RSA_MODULUS, n,
								KEY_PART_RSA_PUB_EXP, e, KEY_PART_END);
	chunk_free(&n);
	chunk_free(&e);
	return success;
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
		gcry_sexp_release(this->key);
		lib->encoding->clear_cache(lib->encoding, this);
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
	this->public.interface.equals = public_key_equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t *this))get_keysize;
	this->public.interface.get_fingerprint = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *fp))get_fingerprint;
	this->public.interface.get_encoding = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *encoding))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*)(public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(public_key_t *this))destroy;

	this->key = NULL;
	this->ref = 1;

	return this;
}

/**
 * Load a public key from components
 */
static gcrypt_rsa_public_key_t *load(chunk_t n, chunk_t e)
{
	private_gcrypt_rsa_public_key_t *this;
	gcry_error_t err;

	this = gcrypt_rsa_public_key_create_empty();
	err = gcry_sexp_build(&this->key, NULL, "(public-key(rsa(n %b)(e %b)))",
						  n.len, n.ptr, e.len, e.ptr);
	if (err)
	{
		DBG1("loading public key failed: %s", gpg_strerror(err));
		free(this);
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
	/** rsa key parameters */
	chunk_t n, e;
};

/**
 * Implementation of builder_t.build
 */
static gcrypt_rsa_public_key_t *build(private_builder_t *this)
{
	gcrypt_rsa_public_key_t *key;

	key = load(this->n, this->e);
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;

	va_start(args, part);
	switch (part)
	{
		case BUILD_RSA_MODULUS:
			this->n = va_arg(args, chunk_t);
			break;
		case BUILD_RSA_PUB_EXP:
			this->e = va_arg(args, chunk_t);
			break;
		default:
			builder_cancel(&this->public);
			break;
	}
	va_end(args);
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

	this->n = this->e = chunk_empty;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;

	return &this->public;
}

