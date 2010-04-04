/*
 * Copyright (C) 2005-2009 Martin Willi
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
#include <crypto/hashers/hasher.h>

#ifdef HAVE_MPZ_POWM_SEC
# undef mpz_powm
# define mpz_powm mpz_powm_sec
#endif

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
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Shared functions defined in gmp_rsa_private_key.c
 */
extern chunk_t gmp_mpz_to_chunk(const mpz_t value);

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
		signature = chunk_skip(signature, 1);
	}

	if (signature.len == 0 || signature.len > this->k)
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
	em = chunk_skip(em, 2);

	/* find magic 0x00 */
	while (em.len > 0)
	{
		if (*em.ptr == 0x00)
		{
			/* found magic byte, stop */
			em = chunk_skip(em, 1);
			break;
		}
		else if (*em.ptr != 0xFF)
		{
			/* bad padding, decryption failed ?!*/
			goto end;
		}
		em = chunk_skip(em, 1);
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
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_emsa_pkcs1_signature(this, HASH_UNKNOWN, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return verify_emsa_pkcs1_signature(this, HASH_MD5, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_emsa_pkcs1_signature(this, HASH_SHA1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA224:
			return verify_emsa_pkcs1_signature(this, HASH_SHA224, data, signature);
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

#define MIN_PS_PADDING 8

/**
 * Implementation of public_key_t.encrypt.
 */
static bool encrypt_(private_gmp_rsa_public_key_t *this, chunk_t plain,
					 chunk_t *crypto)
{
	chunk_t em;
	u_char *pos;
	int padding, i;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (rng == NULL)
	{
		DBG1("no random generator available");
		return FALSE;
	}

	/* number of pseudo-random padding octets */
	padding = this->k - plain.len - 3;
	if (padding < MIN_PS_PADDING)
	{
		DBG1("pseudo-random padding must be at least %d octets", MIN_PS_PADDING);
		return FALSE;
	}

	/* padding according to PKCS#1 7.2.1 (RSAES-PKCS1-v1.5-ENCRYPT) */
	DBG2("padding %u bytes of data to the rsa modulus size of %u bytes",
		 plain.len, this->k);
	em.len = this->k;
	em.ptr = malloc(em.len);
	pos = em.ptr;
	*pos++ = 0x00;
	*pos++ = 0x02;

	/* fill with pseudo random octets */
	rng->get_bytes(rng, padding, pos);

	/* replace zero-valued random octets */
	for (i = 0; i < padding; i++)
	{
		while (*pos == 0)
		{
			rng->get_bytes(rng, 1, pos);
		}
		pos++;
	}
	rng->destroy(rng);

	/* append the padding terminator */
	*pos++ = 0x00;

	/* now add the data */
	memcpy(pos, plain.ptr, plain.len);
	DBG3("padded data before rsa encryption: %B", &em);

	/* rsa encryption using PKCS#1 RSAEP */
	*crypto = rsaep(this, em);
	DBG3("rsa encrypted data: %B", crypto);
	chunk_clear(&em);
	return TRUE;
}

/**
 * Implementation of gmp_rsa_public_key.equals.
 */
static bool equals(private_gmp_rsa_public_key_t *this, public_key_t *other)
{
	return public_key_equals(&this->public.interface, other);
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static size_t get_keysize(private_gmp_rsa_public_key_t *this)
{
	return this->k;
}

/**
 * Implementation of public_key_t.get_encoding
 */
static bool get_encoding(private_gmp_rsa_public_key_t *this,
						 key_encoding_type_t type, chunk_t *encoding)
{
	chunk_t n, e;
	bool success, pem = FALSE;

	if (type == KEY_PUB_PEM)
	{
		pem = TRUE;
		type = KEY_PUB_SPKI_ASN1_DER;
	}

	n = gmp_mpz_to_chunk(this->n);
	e = gmp_mpz_to_chunk(this->e);

	success = lib->encoding->encode(lib->encoding, type, NULL, encoding,
				KEY_PART_RSA_MODULUS, n, KEY_PART_RSA_PUB_EXP, e, KEY_PART_END);
	chunk_free(&n);
	chunk_free(&e);

	if (pem && success)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, KEY_PUB_PEM, NULL,
									encoding, KEY_PART_RSA_PUB_ASN1_DER,
									asn1_encoding, KEY_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

/**
 * Implementation of public_key_t.get_fingerprint
 */
static bool get_fingerprint(private_gmp_rsa_public_key_t *this,
							key_encoding_type_t type, chunk_t *fp)
{
	chunk_t n, e;
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	n = gmp_mpz_to_chunk(this->n);
	e = gmp_mpz_to_chunk(this->e);

	success = lib->encoding->encode(lib->encoding, type, this, fp,
				KEY_PART_RSA_MODULUS, n, KEY_PART_RSA_PUB_EXP, e, KEY_PART_END);
	chunk_free(&n);
	chunk_free(&e);

	return success;
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
		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * See header.
 */
gmp_rsa_public_key_t *gmp_rsa_public_key_load(key_type_t type, va_list args)
{
	private_gmp_rsa_public_key_t *this;
	chunk_t n, e;

	n = e = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (!e.ptr || !n.ptr)
	{
		return NULL;
	}

	this = malloc_thing(private_gmp_rsa_public_key_t);

	this->public.interface.get_type = (key_type_t (*) (public_key_t*))get_type;
	this->public.interface.verify = (bool (*) (public_key_t*, signature_scheme_t, chunk_t, chunk_t))verify;
	this->public.interface.encrypt = (bool (*) (public_key_t*, chunk_t, chunk_t*))encrypt_;
	this->public.interface.equals = (bool (*) (public_key_t*, public_key_t*))equals;
	this->public.interface.get_keysize = (size_t (*) (public_key_t*))get_keysize;
	this->public.interface.get_fingerprint = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *fp))get_fingerprint;
	this->public.interface.has_fingerprint = (bool(*)(public_key_t*, chunk_t fp))public_key_has_fingerprint;
	this->public.interface.get_encoding = (bool(*)(public_key_t*, key_encoding_type_t type, chunk_t *encoding))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*) (public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*) (public_key_t *this))destroy;

	this->ref = 1;

	mpz_init(this->n);
	mpz_init(this->e);

	mpz_import(this->n, n.len, 1, 1, 1, 0, n.ptr);
	mpz_import(this->e, e.len, 1, 1, 1, 0, e.ptr);

	this->k = (mpz_sizeinbase(this->n, 2) + 7) / BITS_PER_BYTE;

	return &this->public;
}

