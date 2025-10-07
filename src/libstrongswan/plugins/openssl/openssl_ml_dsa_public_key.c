/*
 * Copyright (C) 2025 Andreas Steffen
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

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(OPENSSL_NO_ML_DSA)
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "openssl_ml_dsa_public_key.h"

#include <utils/debug.h>

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
	EVP_PKEY *key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Reference counter
	 */
	refcount_t ref;
};

/**
 * Map a key type to an algorithm name
 */
char* openssl_ml_dsa_alg_name(key_type_t type)
{
	switch (type)
	{
		case KEY_ML_DSA_44:
			return "ML-DSA-44";
		case KEY_ML_DSA_65:
			return "ML-DSA-65";
		case KEY_ML_DSA_87:
			return "ML-DSA-87";
		default:
			return NULL;
	}
}

/**
 * Map a key type to an EVP key type
 */
int openssl_ml_dsa_key_type(key_type_t type)
{
	switch (type)
	{
		case KEY_ML_DSA_44:
			return EVP_PKEY_ML_DSA_44;
		case KEY_ML_DSA_65:
			return EVP_PKEY_ML_DSA_65;
		case KEY_ML_DSA_87:
			return EVP_PKEY_ML_DSA_87;
		default:
			return 0;
	}
}

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
	EVP_PKEY_CTX *ctx = NULL;
	EVP_SIGNATURE *sig_alg = NULL;
	OSSL_PARAM ossl_params[] = { OSSL_PARAM_END, OSSL_PARAM_END};
	bool success = FALSE;

	if ((this->type == KEY_ML_DSA_44 && scheme != SIGN_ML_DSA_44) ||
		(this->type == KEY_ML_DSA_65 && scheme != SIGN_ML_DSA_65) ||
		(this->type == KEY_ML_DSA_87 && scheme != SIGN_ML_DSA_87))
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by %N key",
			 signature_scheme_names, scheme, key_type_names, this->type);
		return FALSE;
	}

	/* set PQC signature params */
	if (!pqc_params_create(params, &pqc_params))
	{
		return FALSE;
	}
	if (pqc_params.ctx.len)
	{
		ossl_params[0] = OSSL_PARAM_construct_octet_string(
									OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
									pqc_params.ctx.ptr, pqc_params.ctx.len);
	}

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, this->key, NULL);
	if (!ctx)
	{
		goto error;
	}
	sig_alg = EVP_SIGNATURE_fetch(NULL, openssl_ml_dsa_alg_name(this->type), NULL);

	if (EVP_PKEY_verify_message_init(ctx, sig_alg, ossl_params) <= 0)
	{
		goto error;
	}

	if (EVP_PKEY_verify(ctx, signature.ptr, signature.len, data.ptr, data.len) <= 0)
	{
		goto error;
	}
	success = TRUE;

error:
	pqc_params_free(&pqc_params);
	EVP_SIGNATURE_free(sig_alg);
	EVP_PKEY_CTX_free(ctx);

	return success;
}

METHOD(public_key_t, encrypt, bool,
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
 * Calculate fingerprint from an EdDSA key, also used in ed private key.
 */
bool openssl_ml_dsa_fingerprint(EVP_PKEY *key, cred_encoding_type_t type,
							chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t blob;
	u_char *p;

	if (lib->encoding->get_cache(lib->encoding, type, key, fp))
	{
		return TRUE;
	}
	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			if (!EVP_PKEY_get_raw_public_key(key, NULL, &blob.len))
			{
				return FALSE;
			}
			blob = chunk_alloca(blob.len);
			if (!EVP_PKEY_get_raw_public_key(key, blob.ptr, &blob.len))
			{
				return FALSE;
			}
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			blob = chunk_alloca(i2d_PUBKEY(key, NULL));
			p = blob.ptr;
			i2d_PUBKEY(key, &p);
			break;
		default:
			return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, blob, fp))
	{
		DBG1(DBG_LIB, "SHA1 not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		return FALSE;
	}
	hasher->destroy(hasher);
	lib->encoding->cache(lib->encoding, type, key, fp);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fingerprint)
{
	return openssl_ml_dsa_fingerprint(this->key, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = TRUE;
	u_char *p;

	*encoding = chunk_alloc(i2d_PUBKEY(this->key, NULL));
	p = encoding->ptr;
	i2d_PUBKEY(this->key, &p);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
								NULL, encoding, CRED_PART_EDDSA_PUB_ASN1_DER,
								asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
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
		lib->encoding->clear_cache(lib->encoding, this->key);
		EVP_PKEY_free(this->key);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_public_key_t *create_empty(key_type_t type)
{
	private_public_key_t *this;

	INIT(this,
		.public = {
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
		.type = type,
		.ref = 1,
	);

	return this;
}

/*
 * Described in header
 */
public_key_t *openssl_ml_dsa_public_key_load(key_type_t type, va_list args)
{
	private_public_key_t *this;
	chunk_t pkcs1, blob = chunk_empty;
	EVP_PKEY *key = NULL;

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

	if (blob.len)
	{
		key = EVP_PKEY_new_raw_public_key(openssl_ml_dsa_key_type(type), NULL,
										  blob.ptr, blob.len);
	}
	else if (pkcs1.len)
	{
		key = d2i_PUBKEY(NULL, (const u_char**)&pkcs1.ptr, pkcs1.len);
		if (key && EVP_PKEY_base_id(key) != openssl_ml_dsa_key_type(type))
		{
			EVP_PKEY_free(key);
			return NULL;
		}
	}
	if (!key)
	{
		return NULL;
	}
	this = create_empty(type);
	this->key = key;

	return &this->public;
}

#endif /* OPENSSL_VERSION_NUMBER */
