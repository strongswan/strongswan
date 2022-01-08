/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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

#include "gmalg_ec_public_key.h"
#include "gmalg_util.h"
#include "gmalg_hasher.h"

#include <utils/debug.h>

#include <gmalg.h>

typedef struct private_gmalg_ec_public_key_t private_gmalg_ec_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_gmalg_ec_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	gmalg_ec_public_key_t public;

	/**
	 *  key type
	 */
	key_type_t type;

	/**
	 * the cipher device handle
	 */
	void *hDeviceHandle;

	ECCrefPublicKey pubkey[1];

	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Verification of a signature as in RFC 4754
 */
static bool verify_signature(private_gmalg_ec_public_key_t *this,
							 chunk_t hash, chunk_t signature)
{
	int rc;

	rc = GMALG_ExternalVerify_ECC(this->hDeviceHandle, this->pubkey,
				hash.ptr, hash.len, (ECCSignature *)signature.ptr);
	if (rc)
		return FALSE;

	return TRUE;
}

/**
 * Verify a RFC 4754 signature for a specified curve and hash algorithm
 */
static bool verify_curve_signature(private_gmalg_ec_public_key_t *this,
								signature_scheme_t scheme, int nid_hash,
								int nid_curve, chunk_t data, chunk_t signature)
{
	bool valid = FALSE;
	chunk_t hash = chunk_empty;

	if (HASH_SM3 == nid_hash)
	{
		gmalg_hasher_t *h;

		h = gmalg_hasher_create_ecc(HASH_SM3, &this->pubkey[0], chunk_from_thing(id_default));
		if (h == NULL)
		{
			valid = FALSE;
			goto err;
		}

		valid = h->hasher.allocate_hash(&h->hasher, data, &hash);
		if (valid == FALSE)
			goto err;
	}

	if (hash.ptr)
	{
		valid = verify_signature(this, hash, signature);
		chunk_free(&hash);
		valid = TRUE;
	}
err:
	return valid;
}

METHOD(public_key_t, get_type, key_type_t,
	private_gmalg_ec_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, verify, bool,
	private_gmalg_ec_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_SM2_WITH_SM3:
			return verify_curve_signature(this, scheme, HASH_SM3, KEY_SM2, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported in EC",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt, bool,
	private_gmalg_ec_public_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC public key encryption");

	*plain  = chunk_alloc(crypto.len + ECCref_MAX_LEN * 3); //x+y+m+c,C1C3C2
	GMALG_ExternalEncrytp_ECC(this->hDeviceHandle, this->pubkey,
			crypto.ptr, crypto.len, plain->ptr);

	return TRUE;
}

METHOD(public_key_t, get_keysize, int,
	private_gmalg_ec_public_key_t *this)
{
	return sizeof(ECCrefPublicKey);
}

/**
 * Calculate fingerprint from a EC_KEY, also used in ec private key.
 */
bool gmalg_ec_fingerprint(ECCrefPublicKey *pubkey, cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;
	u_char *p;

	if (lib->encoding->get_cache(lib->encoding, type, pubkey, fp))
	{
		return TRUE;
	}
	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			if(gmalg_i2d_ec_pubkey(pubkey, &key) == FALSE)
				return FALSE;
			break;
		case KEYID_PUBKEY_INFO_SHA1:

			if(gmalg_i2d_ec_pubkey(pubkey, &key) == FALSE)
				return FALSE;

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

	lib->encoding->cache(lib->encoding, type, pubkey, *fp);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_gmalg_ec_public_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return gmalg_ec_fingerprint(this->pubkey, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_gmalg_ec_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;

	gmalg_i2d_ec_pubkey(this->pubkey, encoding);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_ECDSA_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_gmalg_ec_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_gmalg_ec_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		GMALG_CloseDevice(this->hDeviceHandle);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_gmalg_ec_public_key_t *create_empty()
{
	private_gmalg_ec_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.get_keysize = _get_keysize,
				.equals = public_key_equals,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	GMALG_OpenDevice(&this->hDeviceHandle);

	return this;
}

/**
 * See header.
 */
gmalg_ec_public_key_t *gmalg_ec_public_key_load(key_type_t type,
													va_list args)
{
	private_gmalg_ec_public_key_t *this;
	chunk_t blob = chunk_empty;

	if (type != KEY_SM2)
	{
		return NULL;
	}

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

	if (!blob.len)
	{
		return NULL;
	}

	this = create_empty();

	gmalg_d2i_ec_pubkey(this->pubkey, blob);

	this->type =type;

	return &this->public;
}
