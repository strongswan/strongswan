/*
 * Copyright (C) 2009 Martin Willi
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

#include "pkcs1_encoder.h"

#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>

/**
 * Build the SHA1 hash of pubkey(info) ASN.1 data
 */
static bool hash_pubkey(chunk_t pubkey, chunk_t *hash)
{
	hasher_t *hasher;
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		chunk_free(&pubkey);
		DBG1("SHA1 hash algorithm not supported, fingerprinting failed");
		return FALSE;
	}
	hasher->allocate_hash(hasher, pubkey, hash);
	hasher->destroy(hasher);
	chunk_free(&pubkey);
	return TRUE;
}

/**
 * build the fingerprint of the subjectPublicKeyInfo object
 */
static bool build_info_sha1(chunk_t *encoding, va_list args)
{
	chunk_t n, e, pubkey;
	
	if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
						  KEY_PART_RSA_PUB_EXP, &e, KEY_PART_END))
	{
		pubkey = asn1_wrap(ASN1_SEQUENCE, "cm",
					asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
					asn1_bitstring("m",
						asn1_wrap(ASN1_SEQUENCE, "mm",
							asn1_wrap(ASN1_INTEGER, "c", n),
							asn1_wrap(ASN1_INTEGER, "c", e))));
	}
	else
	{
		return FALSE;
	}
	return hash_pubkey(pubkey, encoding);
}

/**
 * build the fingerprint of the subjectPublicKey object
 */
static bool build_sha1(chunk_t *encoding, va_list args)
{
	chunk_t n, e, pubkey;
	
	if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
						  KEY_PART_RSA_PUB_EXP, &e, KEY_PART_END))
	{
		pubkey = asn1_wrap(ASN1_SEQUENCE, "mm",
					asn1_wrap(ASN1_INTEGER, "c", n),
					asn1_wrap(ASN1_INTEGER, "c", e));
	}
	else
	{
		return FALSE;
	}
	return hash_pubkey(pubkey, encoding);
}

/**
 * Encode a public key in PKCS#1/ASN.1 DER
 */
bool build_pub(chunk_t *encoding, va_list args)
{
	chunk_t n, e;
	
	if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
						  KEY_PART_RSA_PUB_EXP, &e, KEY_PART_END))
	{
		*encoding = asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_wrap(ASN1_INTEGER, "c", n),
						asn1_wrap(ASN1_INTEGER, "c", e));
		return TRUE;
	}
	return FALSE;
}

/**
 * Encode a private key in PKCS#1/ASN.1 DER
 */
bool build_priv(chunk_t *encoding, va_list args)
{
	chunk_t n, e, d, p, q, exp1, exp2, coeff;
	
	if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
					KEY_PART_RSA_PUB_EXP, &e, KEY_PART_RSA_PRIV_EXP, &d,
					KEY_PART_RSA_PRIME1, &p, KEY_PART_RSA_PRIME2, &q,
					KEY_PART_RSA_EXP1, &exp1, KEY_PART_RSA_EXP2, &exp2,
					KEY_PART_RSA_COEFF, &coeff, KEY_PART_END))
	{
		*encoding = asn1_wrap(ASN1_SEQUENCE, "cmmssssss",
						ASN1_INTEGER_0,
						asn1_wrap(ASN1_INTEGER, "c", n),
						asn1_wrap(ASN1_INTEGER, "c", e),
						asn1_wrap(ASN1_INTEGER, "c", d),
						asn1_wrap(ASN1_INTEGER, "c", p),
						asn1_wrap(ASN1_INTEGER, "c", q),
						asn1_wrap(ASN1_INTEGER, "c", exp1),
						asn1_wrap(ASN1_INTEGER, "c", exp2),
						asn1_wrap(ASN1_INTEGER, "c", coeff));
		return TRUE;
	}
	return FALSE;
}

/**
 * See header.
 */
bool pkcs1_encoder_encode(key_encoding_type_t type, chunk_t *encoding,
						  va_list args)
{
	switch (type)
	{
		case KEY_ID_PUBKEY_INFO_SHA1:
			return build_info_sha1(encoding, args);
		case KEY_ID_PUBKEY_SHA1:
			return build_sha1(encoding, args);
		case KEY_PUB_ASN1_DER:
			return build_pub(encoding, args);
		case KEY_PRIV_ASN1_DER:
			return build_priv(encoding, args);
		default:
			return FALSE;
	}
}


