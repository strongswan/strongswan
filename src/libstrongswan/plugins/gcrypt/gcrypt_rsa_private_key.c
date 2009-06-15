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

#include "gcrypt_rsa_private_key.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>

typedef struct private_gcrypt_rsa_private_key_t private_gcrypt_rsa_private_key_t;

/**
 * Private data of a gcrypt_rsa_private_key_t object.
 */
struct private_gcrypt_rsa_private_key_t {
	
	/**
	 * Public interface
	 */
	gcrypt_rsa_private_key_t public;
	
	/**
	 * gcrypt S-expression representing an RSA key
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
	 * reference count
	 */
	refcount_t ref;
};

/**
 * Implemented in gcrypt_rsa_public_key.c
 */
public_key_t *gcrypt_rsa_public_key_create_from_sexp(gcry_sexp_t key);

/**
 * find a token in a S-expression
 */
chunk_t gcrypt_rsa_find_token(gcry_sexp_t sexp, char *name)
{
	gcry_sexp_t token;
	chunk_t data = chunk_empty;
	
	token = gcry_sexp_find_token(sexp, name, 1);
	if (token)
	{
		data.ptr = (char*)gcry_sexp_nth_data(token, 1, &data.len);
		if (!data.ptr)
		{
			data.len = 0;
		}
		data = chunk_clone(data);
		gcry_sexp_release(token);
	}
	return data;
}

/**
 * Sign a chunk of data with direct PKCS#1 encoding, no hash OID
 */
static bool sign_raw(private_gcrypt_rsa_private_key_t *this,
					 chunk_t data, chunk_t *signature)
{
	gcry_sexp_t in, out;
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
		DBG1("building signature S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	err = gcry_pk_sign(&out, in, this->key);
	gcry_sexp_release(in);
	if (err)
	{
		DBG1("creating pkcs1 signature failed: %s", gpg_strerror(err));
		return FALSE;
	}
	*signature = gcrypt_rsa_find_token(out, "s");
	gcry_sexp_release(out);
	return !!signature->len;
}

/**
 * Sign a chunk of data using hashing and PKCS#1 encoding
 */
static bool sign_pkcs1(private_gcrypt_rsa_private_key_t *this,
					   hash_algorithm_t hash_algorithm, char *hash_name,
					   chunk_t data, chunk_t *signature)
{
	hasher_t *hasher;
	chunk_t hash;
	gcry_error_t err;
	gcry_sexp_t in, out;
	int hash_oid;
	
	hash_oid = hasher_algorithm_to_oid(hash_algorithm);
	if (hash_oid == OID_UNKNOWN)
	{
		return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm);
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
		DBG1("building signature S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	err = gcry_pk_sign(&out, in, this->key);
	gcry_sexp_release(in);
	if (err)
	{
		DBG1("creating pkcs1 signature failed: %s", gpg_strerror(err));
		return FALSE;
	}
	*signature = gcrypt_rsa_find_token(out, "s");
	gcry_sexp_release(out);
	return !!signature->len;
}

/**
 * Implementation of gcrypt_rsa_private_key.destroy.
 */
static key_type_t get_type(private_gcrypt_rsa_private_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of gcrypt_rsa_private_key.destroy.
 */
static bool sign(private_gcrypt_rsa_private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *sig)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return sign_raw(this, data, sig);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return sign_pkcs1(this, HASH_SHA1, "sha1", data, sig);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return sign_pkcs1(this, HASH_SHA256, "sha256", data, sig);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return sign_pkcs1(this, HASH_SHA384, "sha384", data, sig);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return sign_pkcs1(this, HASH_SHA512, "sha512", data, sig);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return sign_pkcs1(this, HASH_MD5, "md5", data, sig);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of gcrypt_rsa_private_key.destroy.
 */
static bool decrypt(private_gcrypt_rsa_private_key_t *this,
					chunk_t encrypted, chunk_t *plain)
{
	gcry_error_t err;
	gcry_sexp_t in, out;
	chunk_t padded;
	u_char *pos = NULL;;
	
	err = gcry_sexp_build(&in, NULL, "(enc-val(flags)(rsa(a %b)))",
						  encrypted.len, encrypted.ptr);
	if (err)
	{
		DBG1("building decryption S-expression failed: %s", gpg_strerror(err));
		return FALSE;
	}
	err = gcry_pk_decrypt(&out, in, this->key);
	gcry_sexp_release(in);
	if (err)
	{
		DBG1("decrypting pkcs1 data failed: %s", gpg_strerror(err));
		return FALSE;
	}
	padded.ptr = (u_char*)gcry_sexp_nth_data(out, 1, &padded.len);
	/* result is padded, but gcrypt strips leading zero:
	 *  00 | 02 | RANDOM | 00 | DATA */
	if (padded.ptr && padded.len > 2 && padded.ptr[0] == 0x02)
	{
		pos = memchr(padded.ptr, 0x00, padded.len - 1);
		if (pos)
		{
			pos++;
			*plain = chunk_clone(chunk_create(
										pos, padded.len - (pos - padded.ptr)));
		}
	}
	gcry_sexp_release(out);
	if (!pos)
	{
		DBG1("decrypted data has invalid pkcs1 padding");
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of gcrypt_rsa_private_key.get_keysize.
 */
static size_t get_keysize(private_gcrypt_rsa_private_key_t *this)
{
	return gcry_pk_get_nbits(this->key) / 8;
}

/**
 * Implementation of gcrypt_rsa_private_key.destroy.
 */
static identification_t* get_id(private_gcrypt_rsa_private_key_t *this,
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
 * Implementation of gcrypt_rsa_private_key.get_public_key.
 */
static public_key_t* get_public_key(private_gcrypt_rsa_private_key_t *this)
{
	return gcrypt_rsa_public_key_create_from_sexp(this->key);
}

/**
 * Implementation of gcrypt_rsa_private_key.equals.
 */
static bool equals(private_gcrypt_rsa_private_key_t *this, private_key_t *other)
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
 * Implementation of gcrypt_rsa_private_key.belongs_to.
 */
static bool belongs_to(private_gcrypt_rsa_private_key_t *this,
					   public_key_t *public)
{
	identification_t *keyid;
	
	if (public->get_type(public) != KEY_RSA)
	{
		return FALSE;
	}
	keyid = public->get_id(public, ID_PUBKEY_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid))
	{
		return TRUE;
	}
	keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid_info))
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of private_key_t.get_encoding.
 */
static chunk_t get_encoding(private_gcrypt_rsa_private_key_t *this)
{
	chunk_t cp, cq, cd, cexp1 = chunk_empty, cexp2 = chunk_empty;
	gcry_mpi_t p = NULL, q = NULL, d = NULL, exp1, exp2;
	gcry_error_t err;
	
	/* p and q are swapped, gcrypt expects p < q */
	cp = gcrypt_rsa_find_token(this->key, "q");
	cq = gcrypt_rsa_find_token(this->key, "p");
	cd = gcrypt_rsa_find_token(this->key, "d");
	
	err = gcry_mpi_scan(&p, GCRYMPI_FMT_USG, cp.ptr, cp.len, NULL)
		| gcry_mpi_scan(&q, GCRYMPI_FMT_USG, cq.ptr, cq.len, NULL)
		| gcry_mpi_scan(&d, GCRYMPI_FMT_USG, cd.ptr, cd.len, NULL);
	if (err)
	{
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(d);
		chunk_clear(&cp);
		chunk_clear(&cq);
		chunk_clear(&cd);
		DBG1("scanning mpi for export failed: %s", gpg_strerror(err));
		return chunk_empty;
	}
	
	gcry_mpi_sub_ui(p, p, 1);
	exp1 = gcry_mpi_new(gcry_pk_get_nbits(this->key));
	gcry_mpi_mod(exp1, d, p);
	gcry_mpi_release(p);
	
	gcry_mpi_sub_ui(q, q, 1);
	exp2 = gcry_mpi_new(gcry_pk_get_nbits(this->key));
	gcry_mpi_mod(exp1, d, q);
	gcry_mpi_release(q);
	
	err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &cexp1.ptr, &cexp1.len, exp1)
		| gcry_mpi_aprint(GCRYMPI_FMT_USG, &cexp2.ptr, &cexp2.len, exp2);
	
	gcry_mpi_release(d);
	gcry_mpi_release(exp1);
	gcry_mpi_release(exp2);
	
	if (err)
	{
		DBG1("printing mpi for export failed: %s", gpg_strerror(err));
		chunk_clear(&cp);
		chunk_clear(&cq);
		chunk_clear(&cd);
		chunk_clear(&cexp1);
		chunk_clear(&cexp2);
		return chunk_empty;
	}
	
	return asn1_wrap(ASN1_SEQUENCE, "cmmmmmmmm", ASN1_INTEGER_0,
			asn1_integer("m", gcrypt_rsa_find_token(this->key, "n")),
			asn1_integer("m", gcrypt_rsa_find_token(this->key, "e")),
			asn1_integer("m", cd),
			asn1_integer("m", cp),
			asn1_integer("m", cq),
			asn1_integer("m", cexp1),
			asn1_integer("m", cexp2),
			asn1_integer("m", gcrypt_rsa_find_token(this->key, "u")));
}

/**
 * Implementation of gcrypt_rsa_private_key.get_ref.
 */
static private_key_t* get_ref(private_gcrypt_rsa_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
}

/**
 * Implementation of gcrypt_rsa_private_key.destroy.
 */
static void destroy(private_gcrypt_rsa_private_key_t *this)
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
 * Internal generic constructor
 */
static private_gcrypt_rsa_private_key_t *gcrypt_rsa_private_key_create_empty()
{
	private_gcrypt_rsa_private_key_t *this = malloc_thing(private_gcrypt_rsa_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(private_key_t *this))get_type;
	this->public.interface.sign = (bool (*)(private_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t *signature))sign;
	this->public.interface.decrypt = (bool (*)(private_key_t *this, chunk_t crypto, chunk_t *plain))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (private_key_t *this,id_type_t))get_id;
	this->public.interface.get_public_key = (public_key_t* (*)(private_key_t *this))get_public_key;
	this->public.interface.equals = (bool (*) (private_key_t*, private_key_t*))equals;
	this->public.interface.belongs_to = (bool (*) (private_key_t *this, public_key_t *public))belongs_to;
	this->public.interface.get_encoding = (chunk_t(*)(private_key_t*))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*)(private_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(private_key_t *this))destroy;
	
	this->key = NULL;
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * build the keyids of a private/public key
 */
bool gcrypt_rsa_build_keyids(gcry_sexp_t key, identification_t **keyid,
							 identification_t **keyid_info)
{
	chunk_t publicKeyInfo, publicKey, hash;
	hasher_t *hasher;
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1("SHA1 hash algorithm not supported, unable to use RSA");
		return FALSE;
	}
	publicKey = asn1_wrap(ASN1_SEQUENCE, "mm",
				 asn1_integer("m", gcrypt_rsa_find_token(key, "n")),
				 asn1_integer("m", gcrypt_rsa_find_token(key, "e")));
	hasher->allocate_hash(hasher, publicKey, &hash);
	*keyid = identification_create_from_encoding(ID_PUBKEY_SHA1, hash);
	chunk_free(&hash);
	
	publicKeyInfo = asn1_wrap(ASN1_SEQUENCE, "cm",
						asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
						asn1_bitstring("m", publicKey));
	hasher->allocate_hash(hasher, publicKeyInfo, &hash);
	*keyid_info = identification_create_from_encoding(ID_PUBKEY_INFO_SHA1, hash);
	chunk_free(&hash);
	
	hasher->destroy(hasher);
	chunk_free(&publicKeyInfo);
	
	return TRUE;
}

/**
 * Generate an RSA key of specified key size
 */
static gcrypt_rsa_private_key_t *generate(size_t key_size)
{
	private_gcrypt_rsa_private_key_t *this;
	gcry_sexp_t param, key;
	gcry_error_t err;
	
	err = gcry_sexp_build(&param, NULL, "(genkey(rsa(nbits %d)))", key_size);
	if (err)
	{
		DBG1("building S-expression failed: %s", gpg_strerror(err));
		return NULL;
	}
	
	err = gcry_pk_genkey(&key, param);
	gcry_sexp_release(param);
	if (err)
	{
		DBG1("generating RSA key failed: %s", gpg_strerror(err));
		return NULL;
	}
	this = gcrypt_rsa_private_key_create_empty();
	this->key = key;
	
	if (!gcrypt_rsa_build_keyids(this->key, &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

/**
 * ASN.1 definition of a PKCS#1 RSA private key
 */
static const asn1Object_t privkeyObjects[] = {
	{ 0, "RSAPrivateKey",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1,   "version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1,   "modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  2 */
	{ 1,   "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  3 */
	{ 1,   "privateExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  4 */
	{ 1,   "prime1",			ASN1_INTEGER,      ASN1_BODY }, /*  5 */
	{ 1,   "prime2",			ASN1_INTEGER,      ASN1_BODY }, /*  6 */
	{ 1,   "exponent1",			ASN1_INTEGER,      ASN1_BODY }, /*  7 */
	{ 1,   "exponent2",			ASN1_INTEGER,      ASN1_BODY }, /*  8 */
	{ 1,   "coefficient",		ASN1_INTEGER,      ASN1_BODY }, /*  9 */
	{ 1,   "otherPrimeInfos",	ASN1_SEQUENCE,     ASN1_OPT |
												   ASN1_LOOP }, /* 10 */
	{ 2,     "otherPrimeInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
	{ 3,       "prime",			ASN1_INTEGER,      ASN1_BODY }, /* 12 */
	{ 3,       "exponent",		ASN1_INTEGER,      ASN1_BODY }, /* 13 */
	{ 3,       "coefficient",	ASN1_INTEGER,      ASN1_BODY }, /* 14 */
	{ 1,   "end opt or loop",	ASN1_EOC,          ASN1_END  }, /* 15 */
	{ 0, "exit",				ASN1_EOC,          ASN1_EXIT }
};
#define PRIV_KEY_VERSION		 1
#define PRIV_KEY_MODULUS		 2
#define PRIV_KEY_PUB_EXP		 3
#define PRIV_KEY_PRIV_EXP		 4
#define PRIV_KEY_PRIME1			 5
#define PRIV_KEY_PRIME2			 6
#define PRIV_KEY_EXP1			 7
#define PRIV_KEY_EXP2			 8
#define PRIV_KEY_COEFF			 9

/**
 * load private key from a ASN1 encoded blob
 */
static gcrypt_rsa_private_key_t *load(chunk_t blob)
{
	private_gcrypt_rsa_private_key_t *this;
	asn1_parser_t *parser;
	chunk_t object;
	int objectID ;
	bool success = FALSE;
	chunk_t n, e, d, u, p, q;
	gcry_error_t err;
	
	parser = asn1_parser_create(privkeyObjects, blob);
	parser->set_flags(parser, FALSE, TRUE);
	
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PRIV_KEY_VERSION:
				if (object.len > 0 && *object.ptr != 0)
				{
					goto end;
				}
				break;
			case PRIV_KEY_MODULUS:
				n = object;
				break;
			case PRIV_KEY_PUB_EXP:
				e = object;
				break;
			case PRIV_KEY_PRIV_EXP:
				d = object;
				break;
			case PRIV_KEY_PRIME1:
				/* p and q are swapped, as gcrypt expects p < q */
				q = object;
				break;
			case PRIV_KEY_PRIME2:
				p = object;
				break;
			case PRIV_KEY_EXP1:
			case PRIV_KEY_EXP2:
				break;
			case PRIV_KEY_COEFF:
				u = object;
				break;
		}
	}
	success = parser->success(parser);
	
end:
	parser->destroy(parser);
	
	if (!success)
	{
		return NULL;
	}
	
	this = gcrypt_rsa_private_key_create_empty();
	err = gcry_sexp_build(&this->key, NULL,
					"(private-key(rsa(n %b)(e %b)(d %b)(p %b)(q %b)(u %b)))",
					n.len, n.ptr, e.len, e.ptr, d.len, d.ptr,
					p.len, p.ptr, q.len, q.ptr, u.len, u.ptr);
	if (err)
	{
		DBG1("loading private key failed: %s", gpg_strerror(err));
		free(this);
		return NULL;
	}
	err = gcry_pk_testkey(this->key);
	if (err)
	{
		DBG1("private key sanity check failed: %s", gpg_strerror(err));
		destroy(this);
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
 * Builder implementation for key loading/generation
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded/generated private key */
	gcrypt_rsa_private_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static gcrypt_rsa_private_key_t *build(private_builder_t *this)
{
	gcrypt_rsa_private_key_t *key = this->key;
	
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
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_gcrypt_rsa_private_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *gcrypt_rsa_private_key_builder(key_type_t type)
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

