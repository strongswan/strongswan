/*
 * Copyright (C) 2016 Andreas Steffen
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

#include "curve25519_private_key.h"
#include "curve25519_public_key.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>

#define _GNU_SOURCE
#include <stdlib.h>

typedef struct private_curve25519_private_key_t private_curve25519_private_key_t;

/**
 * Private data of a curve25519_private_key_t object.
 */
struct private_curve25519_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	curve25519_private_key_t public;

	/**
	 * Ed25519 private key
	 */
	chunk_t key;

	/**
	 * Ed25519 public key
	 */
	chunk_t pubkey;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_curve25519_private_key_t *this)
{
	return KEY_ED25519;
}

METHOD(private_key_t, sign, bool,
	private_curve25519_private_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t *signature)
{
	if (scheme != SIGN_ED25519)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by Ed25519",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	return FALSE;
}

METHOD(private_key_t, decrypt, bool,
	private_curve25519_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported", encryption_scheme_names,
		 scheme);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_curve25519_private_key_t *this)
{
	return 8 * ED25519_KEY_LEN;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_curve25519_private_key_t *this)
{
	public_key_t *public;
	chunk_t pubkey;

	pubkey = curve25519_public_key_info_encode(this->pubkey);
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ED25519,
								BUILD_BLOB_ASN1_DER, pubkey, BUILD_END);
	free(pubkey.ptr);

	return public;
}

METHOD(private_key_t, get_encoding, bool,
	private_curve25519_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			*encoding = asn1_wrap(ASN1_SEQUENCE, "cms",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(OID_ED25519),
							asn1_wrap(ASN1_OCTET_STRING, "s",
								asn1_simple_object(ASN1_OCTET_STRING, this->key)
							)
						);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_EDDSA_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_fingerprint, bool,
	private_curve25519_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = curve25519_public_key_fingerprint(this->pubkey, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, *fp);
	}
	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_curve25519_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_curve25519_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		chunk_clear(&this->key);
		chunk_free(&this->pubkey);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_curve25519_private_key_t *curve25519_private_key_create(chunk_t key)
{
	private_curve25519_private_key_t *this;
	uint8_t buf[HASH_SIZE_SHA512];
	hasher_t *hasher;

	/* derive public key */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA512);
	if (!hasher || !hasher->get_hash(hasher, key, buf))
	{
		return NULL;
	}
	buf[ 0] &= 0xf8;
	buf[31] &= 0x7f;
	buf[31] |= 0x40;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.key = key,
		.pubkey = chunk_clone(chunk_create(buf, ED25519_KEY_LEN)),
		.ref = 1,
	);

	return this;
}

/**
 * See header.
 */
curve25519_private_key_t *curve25519_private_key_gen(key_type_t type,
													 va_list args)
{
	private_curve25519_private_key_t *this;
	chunk_t key;
	rng_t *rng;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* key_size argument is not needed */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	/* generate 256 bit true random private key */
	rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
	if (!rng || !rng->allocate_bytes(rng, ED25519_KEY_LEN, &key))
	{
		DESTROY_IF(rng);
		return NULL;
	}
	rng->destroy(rng);

	this = curve25519_private_key_create(key);

	return this ? &this->public : NULL;
}

/**
 * See header.
 */
curve25519_private_key_t *curve25519_private_key_load(key_type_t type,
													  va_list args)
{
	private_curve25519_private_key_t *this;
	chunk_t key = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_EDDSA_PRIV_ASN1_DER:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!asn1_parse_simple_object(&key, ASN1_OCTET_STRING, 0, "EdPrivateKey") ||
		key.len != ED25519_KEY_LEN)
	{
		return NULL;
	}
	this = curve25519_private_key_create(chunk_clone(key));

	return this ? &this->public : NULL;
}
