/*
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 
#include <gmp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "gmp_rsa_public_key.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/pem.h>
#include <crypto/hashers/hasher.h>
#include <pgp/pgp.h>

typedef struct private_gmp_rsa_public_key_t private_gmp_rsa_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_gmp_rsa_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	gmp_rsa_public_key_t public;
	
	/**
	 * Public modulus.
	 */
	mpz_t n;
	
	/**
	 * Public exponent.
	 */
	mpz_t e;
	
	/**
	 * Keysize in bytes.
	 */
	size_t k;
	
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
 * Shared functions defined in gmp_rsa_private_key.c
 */
extern chunk_t gmp_mpz_to_chunk(const mpz_t value);
extern chunk_t gmp_mpz_to_asn1(const mpz_t value);

/**
 * RSAEP algorithm specified in PKCS#1.
 */
static chunk_t rsaep(private_gmp_rsa_public_key_t *this, chunk_t data)
{
	mpz_t m, c;
	chunk_t encrypted;
	
	mpz_init(c);
	mpz_init(m);
	
	mpz_import(m, data.len, 1, 1, 1, 0, data.ptr);
	
	mpz_powm(c, m, this->e, this->n);

	encrypted.len = this->k;
	encrypted.ptr = mpz_export(NULL, NULL, 1, encrypted.len, 1, 0, c);
	if (encrypted.ptr == NULL)
	{
		encrypted.len = 0;
	}
	
	mpz_clear(c);
	mpz_clear(m);
	
	return encrypted;
}

/**
 * RSAVP1 algorithm specified in PKCS#1.
 */
static chunk_t rsavp1(private_gmp_rsa_public_key_t *this, chunk_t data)
{
	return rsaep(this, data);
}

/**
 * ASN.1 definition of digestInfo
 */
static const asn1Object_t digestInfoObjects[] = {
	{ 0, "digestInfo",			ASN1_SEQUENCE,		ASN1_OBJ  }, /*  0 */
	{ 1,   "digestAlgorithm",	ASN1_EOC,			ASN1_RAW  }, /*  1 */
	{ 1,   "digest",			ASN1_OCTET_STRING,	ASN1_BODY }, /*  2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT }
};
#define DIGEST_INFO					0
#define DIGEST_INFO_ALGORITHM		1
#define DIGEST_INFO_DIGEST			2

/**
 * Verification of an EMPSA PKCS1 signature described in PKCS#1
 */
static bool verify_emsa_pkcs1_signature(private_gmp_rsa_public_key_t *this,
										hash_algorithm_t algorithm,
										chunk_t data, chunk_t signature)
{
	chunk_t em_ori, em;
	bool success = FALSE;
	
	/* remove any preceding 0-bytes from signature */
	while (signature.len && *(signature.ptr) == 0x00)
	{
		signature.len -= 1;
		signature.ptr++;
	}
	
	if (signature.len > this->k)
	{
		return INVALID_ARG;
	}
	
	/* unpack signature */
	em_ori = em = rsavp1(this, signature);
	
	/* result should look like this:
	 * EM = 0x00 || 0x01 || PS || 0x00 || T. 
	 * PS = 0xFF padding, with length to fill em
	 * T = oid || hash
	 */
	
	/* check magic bytes */
	if (*(em.ptr) != 0x00 || *(em.ptr+1) != 0x01)
	{
		goto end;
	}
	em.ptr += 2;
	em.len -= 2;
	
	/* find magic 0x00 */
	while (em.len > 0)
	{
		if (*em.ptr == 0x00)
		{
			/* found magic byte, stop */
			em.ptr++;
			em.len--;
			break;
		}
		else if (*em.ptr != 0xFF)
		{
			/* bad padding, decryption failed ?!*/
			goto end;
		}
		em.ptr++;
		em.len--;
	}

	if (em.len == 0)
	{
		/* no digestInfo found */
		goto end;
	}

	if (algorithm == HASH_UNKNOWN)
	{   /* IKEv1 signatures without digestInfo */
		if (em.len != data.len)
		{
			DBG1("hash size in signature is %u bytes instead of %u bytes",
				 em.len, data.len);
			goto end;
		}
		success = memeq(em.ptr, data.ptr, data.len);
	}
	else
	{   /* IKEv2 and X.509 certificate signatures */
		asn1_parser_t *parser;
		chunk_t object;
		int objectID;
		hash_algorithm_t hash_algorithm = HASH_UNKNOWN;

		DBG2("signature verification:");
		parser = asn1_parser_create(digestInfoObjects, em);

		while (parser->iterate(parser, &objectID, &object))
		{
			switch (objectID)
			{
				case DIGEST_INFO:
				{
					if (em.len > object.len)
					{
						DBG1("digestInfo field in signature is followed by %u surplus bytes",
							 em.len - object.len);
						goto end_parser;
					}
					break;
				}
				case DIGEST_INFO_ALGORITHM:
				{
					int hash_oid = asn1_parse_algorithmIdentifier(object,
										 parser->get_level(parser)+1, NULL);

					hash_algorithm = hasher_algorithm_from_oid(hash_oid);
					if (hash_algorithm == HASH_UNKNOWN || hash_algorithm != algorithm)
					{
						DBG1("expected hash algorithm %N, but found %N (OID: %#B)",
							 hash_algorithm_names, algorithm,
							 hash_algorithm_names, hash_algorithm,  &object);
						goto end_parser;
					}
					break;
				}
				case DIGEST_INFO_DIGEST:
				{
					chunk_t hash;
					hasher_t *hasher;
					
					hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm);
					if (hasher == NULL)
					{
						DBG1("hash algorithm %N not supported",
							 hash_algorithm_names, hash_algorithm);
						goto end_parser;
					}

					if (object.len != hasher->get_hash_size(hasher))
					{
						DBG1("hash size in signature is %u bytes instead of %u "
							 "bytes", object.len, hasher->get_hash_size(hasher));
						hasher->destroy(hasher);
						goto end_parser;
					}

					/* build our own hash and compare */
					hasher->allocate_hash(hasher, data, &hash);
					hasher->destroy(hasher);
					success = memeq(object.ptr, hash.ptr, hash.len);
					free(hash.ptr);
					break;
				}
				default:
					break;
			}
		}

end_parser:
		success &= parser->success(parser);
		parser->destroy(parser);
	}

end:
	free(em_ori.ptr);
	return success;
}

/**
 * Implementation of public_key_t.get_type.
 */
static key_type_t get_type(private_gmp_rsa_public_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of public_key_t.verify.
 */
static bool verify(private_gmp_rsa_public_key_t *this, signature_scheme_t scheme, 
				   chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_DEFAULT:
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_emsa_pkcs1_signature(this, HASH_UNKNOWN, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return verify_emsa_pkcs1_signature(this, HASH_MD5, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_emsa_pkcs1_signature(this, HASH_SHA1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return verify_emsa_pkcs1_signature(this, HASH_SHA256, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return verify_emsa_pkcs1_signature(this, HASH_SHA384, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return verify_emsa_pkcs1_signature(this, HASH_SHA512, data, signature);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static bool encrypt_(private_gmp_rsa_public_key_t *this, chunk_t crypto, chunk_t *plain)
{
	DBG1("RSA public key encryption not implemented");
	return FALSE;
}

/**
 * Implementation of gmp_rsa_public_key.equals.
 */
static bool equals(private_gmp_rsa_public_key_t *this, public_key_t *other)
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
static size_t get_keysize(private_gmp_rsa_public_key_t *this)
{
	return this->k;
}

/**
 * Build the PGP version 3 RSA key identifier from n and e using
 * MD5 hashed modulus and exponent. Also used in rsa_private_key.c.
 */
static identification_t* gmp_rsa_build_pgp_v3_keyid(mpz_t n, mpz_t e)
{
	identification_t *keyid;
	chunk_t modulus, mod, exponent, exp, hash;
	hasher_t *hasher;
	
	hasher= lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	if (hasher == NULL)
	{
		DBG1("computation of PGP V3 keyid failed, no MD5 hasher is available");
		return NULL;
	}
	mod = modulus  = gmp_mpz_to_chunk(n);
	exp = exponent = gmp_mpz_to_chunk(e);

	/* remove leading zero bytes before hashing modulus and exponent */
	while (mod.len > 0 && *mod.ptr == 0x00)
	{
		mod.ptr++;
		mod.len--;
	} 
	while (exp.len > 0 && *exp.ptr == 0x00)
	{
		exp.ptr++;
		exp.len--;
	} 
	hasher->allocate_hash(hasher, mod, NULL);
	hasher->allocate_hash(hasher, exp, &hash);
	hasher->destroy(hasher);
	keyid = identification_create_from_encoding(ID_KEY_ID, hash);
	free(hash.ptr);
	free(modulus.ptr);
	free(exponent.ptr);
	return keyid;
}

/**
 * Implementation of public_key_t.get_id.
 */
static identification_t *get_id(private_gmp_rsa_public_key_t *this,
								id_type_t type)
{
	switch (type)
	{
		case ID_PUBKEY_INFO_SHA1:
			return this->keyid_info;
		case ID_PUBKEY_SHA1:
			return this->keyid;
		case ID_KEY_ID:
			return gmp_rsa_build_pgp_v3_keyid(this->n, this->e);
		default:
			return NULL;
	}
}

/*
 * Implementation of public_key_t.get_encoding.
 */
static chunk_t get_encoding(private_gmp_rsa_public_key_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
					 gmp_mpz_to_asn1(this->n),
					 gmp_mpz_to_asn1(this->e));
}

/**
 * Implementation of public_key_t.get_ref.
 */
static private_gmp_rsa_public_key_t* get_ref(private_gmp_rsa_public_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of gmp_rsa_public_key.destroy.
 */
static void destroy(private_gmp_rsa_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		mpz_clear(this->n);
		mpz_clear(this->e);
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_gmp_rsa_public_key_t *gmp_rsa_public_key_create_empty()
{
	private_gmp_rsa_public_key_t *this = malloc_thing(private_gmp_rsa_public_key_t);
	
	this->public.interface.get_type = (key_type_t (*) (public_key_t*))get_type;
	this->public.interface.verify = (bool (*) (public_key_t*, signature_scheme_t, chunk_t, chunk_t))verify;
	this->public.interface.encrypt = (bool (*) (public_key_t*, chunk_t, chunk_t*))encrypt_;
	this->public.interface.equals = (bool (*) (public_key_t*, public_key_t*))equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t*))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (public_key_t*, id_type_t))get_id;
	this->public.interface.get_encoding = (chunk_t(*) (public_key_t*))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*) (public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*) (public_key_t *this))destroy;
	
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Build the RSA key identifier from n and e using SHA1 hashed publicKey(Info).
 * Also used in rsa_private_key.c.
 */
bool gmp_rsa_public_key_build_id(mpz_t n, mpz_t e, identification_t **keyid,
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
	publicKey = asn1_wrap(ASN1_SEQUENCE, "mm",
					gmp_mpz_to_asn1(n),
					gmp_mpz_to_asn1(e));
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
 * Create a public key from mpz values, used in gmp_rsa_private_key
 */
gmp_rsa_public_key_t *gmp_rsa_public_key_create_from_n_e(mpz_t n, mpz_t e)
{
	private_gmp_rsa_public_key_t *this = gmp_rsa_public_key_create_empty();

	mpz_init_set(this->n, n);
	mpz_init_set(this->e, e);
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) /  BITS_PER_BYTE;
	if (!gmp_rsa_public_key_build_id(this->n, this->e,
									 &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
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
 * Load a public key from an ASN.1 encoded blob
 */
static gmp_rsa_public_key_t *load_asn1_der(chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	private_gmp_rsa_public_key_t *this = gmp_rsa_public_key_create_empty();

	mpz_init(this->n);
	mpz_init(this->e);
	
	parser = asn1_parser_create(pubkeyObjects, blob);
	
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case PUB_KEY_MODULUS:
				mpz_import(this->n, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PUB_KEY_EXPONENT:
				mpz_import(this->e, object.len, 1, 1, 1, 0, object.ptr);
				break;
		}
	}
	success = parser->success(parser);
	free(blob.ptr);
	parser->destroy(parser);

	if (!success)
	{
		destroy(this);
		return NULL;
	}
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) /  BITS_PER_BYTE;

	if (!gmp_rsa_public_key_build_id(this->n, this->e,
									 &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * Load a public key from an OpenPGP blob
 */
static gmp_rsa_public_key_t* load_pgp(chunk_t blob)
{
	chunk_t exponent, modulus;
	chunk_t packet = blob;
	private_gmp_rsa_public_key_t *this = gmp_rsa_public_key_create_empty();

	mpz_init(this->n);
	mpz_init(this->e);
	
	/* modulus n */
	modulus.len = (pgp_length(&packet, 2) + 7) / BITS_PER_BYTE;
	modulus.ptr = packet.ptr;
	if (modulus.len > packet.len)
	{
		DBG1("OpenPGP public key blob too short for modulus");
		goto end;
	}
	packet.ptr += modulus.len;
	packet.len -= modulus.len;
	DBG2("L3 - modulus:");
	DBG3("%B", &modulus);

	/* public exponent e */
	exponent.len = (pgp_length(&packet, 2) + 7) /  BITS_PER_BYTE;
	exponent.ptr = packet.ptr;
	if (exponent.len > packet.len)
	{
		DBG1("OpenPGP public key blob too short for exponent");
		goto end;
	}
	DBG2("L3 - public exponent:");
	DBG3("%B", &exponent);

	mpz_import(this->n, modulus.len,  1, 1, 1, 0, modulus.ptr);
	mpz_import(this->e, exponent.len, 1, 1, 1, 0, exponent.ptr);
	this->k = (mpz_sizeinbase(this->n, 2) + 7) /  BITS_PER_BYTE;
	free(blob.ptr);

	if (!gmp_rsa_public_key_build_id(this->n, this->e,
									 &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;

end:
	free(blob.ptr);
	destroy(this);
	return NULL;
}

/**
 * Load a public key from an RFC 3110 encoded blob
 */
static gmp_rsa_public_key_t *load_rfc_3110(chunk_t blob)
{
	chunk_t exponent, modulus;
	u_char *pos = blob.ptr;
	size_t len  = blob.len;
	private_gmp_rsa_public_key_t *this = gmp_rsa_public_key_create_empty();
	
	mpz_init(this->n);
	mpz_init(this->e);

	if (blob.len < 3)
	{
		DBG1("RFC 3110 public key blob too short for exponent length");
		goto end;
	}
	if (pos[0] != 0x00)
	{
		exponent = chunk_create(pos + 1, pos[0]);
		pos++;
		len--;
	}
	else
	{
		exponent = chunk_create(pos + 3, 256*pos[1] + pos[2]);
		pos += 3;
		len -= 3;
	}
	if (exponent.len > len)
	{
		DBG1("RFC 3110 public key blob too short for exponent");
		goto end;
	}
	pos += exponent.len;
	len -= exponent.len;

	if (len == 0)
	{
		DBG1("RFC 3110 public key blob has zero length modulus");
		goto end;
	}	
	modulus = chunk_create(pos, len);

	mpz_import(this->n, modulus.len,  1, 1, 1, 0, modulus.ptr);
	mpz_import(this->e, exponent.len, 1, 1, 1, 0, exponent.ptr);
	this->k = (mpz_sizeinbase(this->n, 2) + 7) /  BITS_PER_BYTE;
	free(blob.ptr);

	if (!gmp_rsa_public_key_build_id(this->n, this->e,
									 &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;

end:
	free(blob.ptr);
	destroy(this);
	return NULL;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded public key */
	gmp_rsa_public_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static gmp_rsa_public_key_t *build(private_builder_t *this)
{
	gmp_rsa_public_key_t *key = this->key;
	
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
				this->key = load_asn1_der(chunk_clone(chunk));
				va_end(args);
				return;
			}
			case BUILD_BLOB_PGP:
			{
				va_start(args, part);
				chunk = va_arg(args, chunk_t);
				this->key = load_pgp(chunk_clone(chunk));
				va_end(args);
				return;
			}
			case BUILD_BLOB_RFC_3110:
			{
				va_start(args, part);
				chunk = va_arg(args, chunk_t);
				this->key = load_rfc_3110(chunk_clone(chunk));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_gmp_rsa_public_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *gmp_rsa_public_key_builder(key_type_t type)
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

