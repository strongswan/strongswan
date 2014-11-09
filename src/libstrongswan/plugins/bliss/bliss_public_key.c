/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "bliss_public_key.h"
#include "bliss_param_set.h"

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>

typedef struct private_bliss_public_key_t private_bliss_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_bliss_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	bliss_public_key_t public;

	/**
	 * BLISS signature parameter set
	 */
	bliss_param_set_t *set;

	/**
	 * BLISS public key a (coefficients of polynomial (2g + 1)/f)
	 */
	uint32_t *a;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_bliss_public_key_t *this)
{
	return KEY_BLISS;
}

METHOD(public_key_t, verify, bool,
	private_bliss_public_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_BLISS_WITH_SHA512:
			return FALSE;
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported by BLISS",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt_, bool,
	private_bliss_public_key_t *this, encryption_scheme_t scheme,
	chunk_t plain, chunk_t *crypto)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_bliss_public_key_t *this)
{
	return this->set->strength;
}

/**
 * Parse an ASN.1 OCTET STRING into an array of public key coefficients
 */
uint32_t* bliss_public_key_from_asn1(chunk_t object, int n)
{
	uint32_t *pubkey;
	uint16_t coeff;
	u_char *pos;
	int i;

	pubkey = malloc(n * sizeof(uint32_t));
	pos = object.ptr;

	for (i = 0; i < n; i++)
	{
		coeff = untoh16(pos);
		pubkey[i] = (uint32_t)coeff;
		pos += 2;
	}

	return pubkey;
}

/**
 * Encode a raw BLISS subjectPublicKey in ASN.1 DER format
 */
chunk_t bliss_public_key_encode(uint32_t *pubkey, int n)
{
	u_char *pos;
	chunk_t encoding;
	int i;

	pos = asn1_build_object(&encoding, ASN1_OCTET_STRING, 2 * n);

	for (i = 0; i < n; i++)
	{
		htoun16(pos, (uint16_t)pubkey[i]);
		pos += 2;
	}

	return encoding;
}

/**
 * Encode a BLISS subjectPublicKeyInfo record in ASN.1 DER format
 */
chunk_t bliss_public_key_info_encode(int oid, uint32_t *pubkey, int n)
{
	chunk_t encoding, pubkey_encoding;

	pubkey_encoding = bliss_public_key_encode(pubkey, n);

	encoding = asn1_wrap(ASN1_SEQUENCE, "mm",
					asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_build_known_oid(OID_BLISS_PUBLICKEY),
						asn1_build_known_oid(oid)),
					asn1_bitstring("m", pubkey_encoding));

	return encoding;
}

/**
 * Generate a BLISS public key fingerprint
 */
bool bliss_public_key_fingerprint(int oid, uint32_t *pubkey, int n,
								  cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			key = bliss_public_key_encode(pubkey, n);
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			key = bliss_public_key_info_encode(oid, pubkey, n);
			break;
		default:
			return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, key, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		free(key.ptr);

		return FALSE;
	}
	hasher->destroy(hasher);
	free(key.ptr);

	return TRUE;
}

METHOD(public_key_t, get_encoding, bool,
	private_bliss_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;

	*encoding = bliss_public_key_info_encode(this->set->oid, this->a,
											 this->set->n);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_BLISS_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_bliss_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = bliss_public_key_fingerprint(this->set->oid, this->a,
										   this->set->n, type, fp);
	lib->encoding->cache(lib->encoding, type, this, *fp);

	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_bliss_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_bliss_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		free(this->a);
		free(this);
	}
}

/**
 * ASN.1 definition of a BLISS public key
 */
static const asn1Object_t pubkeyObjects[] = {
	{ 0, "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_OBJ  }, /*  0 */
	{ 1,   "algorithm",			ASN1_EOC,			ASN1_RAW  }, /*  1 */
	{ 1,   "subjectPublicKey",	ASN1_BIT_STRING,	ASN1_BODY }, /*  2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT }
};
#define BLISS_SUBJECT_PUBLIC_KEY_ALGORITHM	1
#define BLISS_SUBJECT_PUBLIC_KEY			2

/**
 * See header.
 */
bliss_public_key_t *bliss_public_key_load(key_type_t type, va_list args)
{
	private_bliss_public_key_t *this;
	chunk_t blob = chunk_empty, object, param;
	asn1_parser_t *parser;
	bool success = FALSE;
	int objectID, oid;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (blob.len == 0)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt_,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	parser = asn1_parser_create(pubkeyObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case BLISS_SUBJECT_PUBLIC_KEY_ALGORITHM:
			{
				oid = asn1_parse_algorithmIdentifier(object,
								parser->get_level(parser)+1, &param);
				if (oid != OID_BLISS_PUBLICKEY)
				{
					goto end;
				}
				if (!asn1_parse_simple_object(&param, ASN1_OID,
								parser->get_level(parser)+3, "blissKeyType"))
				{
					goto end;
				}
				oid = asn1_known_oid(param);
				if (oid == OID_UNKNOWN)
				{
					goto end;
				}
				this->set = bliss_param_set_get_by_oid(oid);
				if (this->set == NULL)
				{
					goto end;
				}
				break;
			}
			case BLISS_SUBJECT_PUBLIC_KEY:
				if (object.len > 0 && *object.ptr == 0x00)
				{
					/* skip initial bit string octet defining 0 unused bits */
					object = chunk_skip(object, 1);
				}
				if (!asn1_parse_simple_object(&object, ASN1_OCTET_STRING,
						parser->get_level(parser)+1, "blissPublicKey"))
				{
					goto end;
				}
				if (object.len != 2*this->set->n)
				{
					goto end;
				}
				this->a = bliss_public_key_from_asn1(object, this->set->n);
				break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}
