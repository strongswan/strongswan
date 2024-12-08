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
#include <credentials/keys/signature_params.h>

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
	pqc_params_t pqc_params;
	int ret, result;

	if (key_type_from_signature_scheme(scheme) != this->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
					   signature_scheme_names, scheme);
		return FALSE;
	}

	/* set PQC signature params */
	if (!pqc_params_create(params, &pqc_params))
	{
		return FALSE;
	}

	ret = wc_dilithium_verify_ctx_msg(signature.ptr, signature.len,
									  pqc_params.ctx.ptr, pqc_params.ctx.len,
									  data.ptr, data.len, &result, &this->key);
	pqc_params_free(&pqc_params);

	return (ret == 0) && (result == 1);
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
	return BITS_PER_BYTE * get_public_key_size(this->type);
}

/**
 * Generate two types of ML-DSA fingerprints
 */
bool wolfssl_ml_dsa_fingerprint(dilithium_key *key, key_type_t type,
								cred_encoding_type_t enc_type, chunk_t *fp)
{
	chunk_t pubkey = chunk_empty, encoding = chunk_empty;
	hasher_t *hasher;
	int len;
	bool success = FALSE;

	*fp = chunk_empty;
	len = get_public_key_size(type);
	pubkey = chunk_alloc(len);

	if (wc_dilithium_export_public(key, pubkey.ptr, &len) != 0)
	{
		goto end;
	}

	switch (enc_type)
	{
		case KEYID_PUBKEY_SHA1:
			encoding = chunk_clone(pubkey);
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			encoding = public_key_info_encode(pubkey, key_type_to_oid(type));
			break;
		default:
			goto end;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, encoding, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported");
		DESTROY_IF(hasher);
		goto end;
	}
	hasher->destroy(hasher);
	success = TRUE;

end:
	chunk_free(&pubkey);
	chunk_free(&encoding);

	return success;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}

	success = wolfssl_ml_dsa_fingerprint(&this->key, this->type, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}

	return success;
}


METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = FALSE;
	chunk_t pubkey;
	int len, oid;

	len = get_public_key_size(this->type);
	pubkey = chunk_alloc(len);

	if (wc_dilithium_export_public(&this->key, pubkey.ptr, &len) != 0)
	{
		*encoding = chunk_empty;
		goto end;
	}

	oid = key_type_to_oid(this->type);
	*encoding = public_key_info_encode(pubkey, oid);
	success = TRUE;

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}

end:
	chunk_free(&pubkey);

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
		free(this);
	}
}

/**
 * Checks if a given ML-DSA type is enabled and sets some parameters
 */
bool wolfssl_ml_dsa_enabled(key_type_t type, uint8_t *level)
{
	*level = 0;

	if (type == KEY_ML_DSA_44)
	{
#ifndef WOLFSSL_NO_ML_DSA_44
		*level = WC_ML_DSA_44;
#endif
	}
	else if (type == KEY_ML_DSA_65)
	{
#ifndef WOLFSSL_NO_ML_DSA_65
		*level = WC_ML_DSA_65;
#endif
	}
	else if (type == KEY_ML_DSA_87)
	{
#ifndef WOLFSSL_NO_ML_DSA_87
		*level = WC_ML_DSA_87;
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

	if (wc_dilithium_init(&this->key) != 0 ||
	   (level && wc_dilithium_set_level(&this->key, level) != 0))
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
	chunk_t pkcs1, blob = chunk_empty;
	uint8_t level = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				pkcs1 = va_arg(args, chunk_t);
				type = public_key_info_decode(pkcs1, &blob);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!wolfssl_ml_dsa_enabled(type, &level) || blob.len == 0)
	{
		return NULL;
	}

	this = create_empty(type, level);
	if (!this)
	{
		return NULL;
	}

	if (wc_dilithium_import_public(blob.ptr, blob.len, &this->key) != 0)
	{
		DBG1(DBG_LIB, "importing ML-DSA public key failed");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
#endif /* HAVE_DILITHIUM */
