/*
  * Copyright (C) 2024 Andreas Steffen, strongSec GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

#include "wolfssl_common.h"

#if defined(HAVE_DILITHIUM)

#include "wolfssl_ml_dsa_public_key.h"

#include <utils/debug.h>
#include <asn1/asn1.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dilithium.h>

typedef struct private_public_key_t private_public_key_t;

/**
 * Private data
 */
struct private_public_key_t {

	/**
	 * Public interface
	 */
	public_key_t public;

	/**
	 * Key object
	 */
	dilithium_key key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Public key
	 */
	chunk_t pubkey;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, verify, bool,
	private_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	return FALSE;
}

METHOD(public_key_t, encrypt_, bool,
	private_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported", encryption_scheme_names,
		 scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_public_key_t *this)
{
	return BITS_PER_BYTE * this->pubkey.len;
}

static chunk_t public_key_info_encode(chunk_t pubkey, int oid)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_algorithmIdentifier(oid),
						asn1_bitstring("c", pubkey)
					 );
}

/**
 * Generate twoo types of ML-DSA fingerprints
 */
bool wolfssl_ml_dsa_fingerprint(chunk_t pubkey, int oid,
								cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			key = chunk_clone(pubkey);
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			key = public_key_info_encode(pubkey, oid);
			break;
		default:
			return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, key, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported");
		DESTROY_IF(hasher);
		free(key.ptr);
		return FALSE;
	}
	hasher->destroy(hasher);
	chunk_free(&key);

	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success;
	int oid;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	oid = key_type_to_oid(this->type);
	success = wolfssl_ml_dsa_fingerprint(this->pubkey, oid, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}

	return success;
}

METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = TRUE;

	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(public_key_t, destroy, void,
	private_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		wc_dilithium_free(&this->key);
		chunk_free(&this->pubkey);
		free(this);
	}
}

/**
 * Checks if a given ML-DSA type is enabled and sets some parameters
 */
bool wolfssl_ml_dsa_enabled(key_type_t type, uint8_t *level, size_t *pubkey_len)
{
	*level = 0;

	if (type == KEY_ANY)
	{
		return TRUE;
	}
	else if (type == KEY_ML_DSA_44)
	{
#ifndef WOLFSSL_NO_ML_DSA_44
		*level = WC_ML_DSA_44;
		*pubkey_len = ML_DSA_LEVEL2_PUB_KEY_SIZE;
#endif
	}
	else if (type == KEY_ML_DSA_65)
	{
#ifndef WOLFSSL_NO_ML_DSA_65
		*level = WC_ML_DSA_65;
		*pubkey_len = ML_DSA_LEVEL3_PUB_KEY_SIZE;
#endif
	}
	else if (type == KEY_ML_DSA_87)
	{
#ifndef WOLFSSL_NO_ML_DSA_87
		*level = WC_ML_DSA_87;
		*pubkey_len = ML_DSA_LEVEL5_PUB_KEY_SIZE;
#endif
	}

	return *level != 0;
}

/**
 * Generic private constructor
 */
static private_public_key_t *create_empty(key_type_t type, uint8_t level)
{
	private_public_key_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.verify = _verify,
			.encrypt = _encrypt_,
			.get_keysize = _get_keysize,
			.equals = public_key_equals,
			.get_fingerprint = _get_fingerprint,
			.has_fingerprint = public_key_has_fingerprint,
			.get_encoding = _get_encoding,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.type = type,
		.ref = 1,
	);

	if (wc_dilithium_init(&this->key) ||
	   (level && wc_dilithium_set_level(&this->key, level)))
	{
		free(this);
		return NULL;
	}

	return this;
}

/*
 * Described in header
 */
public_key_t *wolfssl_ml_dsa_public_key_load(key_type_t type, va_list args)
{
	private_public_key_t *this;
	chunk_t asn1 = chunk_empty, blob = chunk_empty;
	uint8_t level = 0;
	size_t pubkey_len = 0;
	int ret, len, idx = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				asn1 = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if ((blob.len == 0 && asn1.len == 0) ||
		!wolfssl_ml_dsa_enabled(type, &level, &pubkey_len))
	{
		return NULL;
	}

	this = create_empty(type, level);
	if (!this)
	{
		return NULL;
	}

	if (blob.len > 0)
	{
		/* raw public key */
		ret = wc_dilithium_import_public(blob.ptr, blob.len, &this->key);
		if (ret)
		{
			DBG1(DBG_LIB, "importing ML-DSA public key failed: %d", ret);
			destroy(this);
			return NULL;
		}
		this->pubkey = chunk_clone(blob);
	}
	else
	{
		/* PKCS#1-encoded public key in ASN.1 DER format */
		this->pubkey = chunk_alloc(pubkey_len);
		len = pubkey_len;

		if (wc_Dilithium_PublicKeyDecode(asn1.ptr, &idx, &this->key, asn1.len) ||
			wc_dilithium_export_public(&this->key, this->pubkey.ptr, &len))
		{
			DBG1(DBG_LIB, "decoding ML-DSA public key failed");
			destroy(this);
			return NULL;
		}
	}

	return &this->public;
}
#endif /* HAVE_DILITHIUM */
