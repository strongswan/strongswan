/*
 * Copyright (C) 2024-2025 Andreas Steffen, strongSec GmbH
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

#include "wolfssl_ml_dsa_private_key.h"

#include <utils/debug.h>
#include <asn1/asn1.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>
#include <credentials/keys/signature_params.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dilithium.h>

typedef struct private_private_key_t private_private_key_t;

/**
 * Private data
 */
struct private_private_key_t {

	/**
	 * Public interface
	 */
	private_key_t public;

	/**
	 * Key object
	 */
	dilithium_key key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Secret key seed
	 */
	chunk_t keyseed;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

/* from wolfss_ml_dsa_public_key.c */
bool wolfssl_ml_dsa_enabled(key_type_t type, uint8_t *level);
bool wolfssl_ml_dsa_fingerprint(dilithium_key *key, key_type_t type,
								cred_encoding_type_t enc_type, chunk_t *fp);

METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	pqc_params_t pqc_params;
	u_int sig_len;
	int ret;

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

	sig_len = wc_dilithium_sig_size(&this->key);
	*signature = chunk_alloc(sig_len);

	/* deterministic or randomized signature? */
	if 	(pqc_params.deterministic)
	{
		uint8_t seed[DILITHIUM_RND_SZ];

		memset(seed, 0x00, DILITHIUM_RND_SZ);
		ret = wc_dilithium_sign_ctx_msg_with_seed(pqc_params.ctx.ptr,
							pqc_params.ctx.len, data.ptr, data.len,
							signature->ptr, &sig_len, &this->key, seed);
	}
	else
	{
		WC_RNG rng;

		if (wc_InitRng(&rng) != 0)
		{
			DBG1(DBG_LIB, "initializing random generator failed");
			pqc_params_free(&pqc_params);
			return NULL;
		}
		ret = wc_dilithium_sign_ctx_msg(pqc_params.ctx.ptr,
							pqc_params.ctx.len, data.ptr, data.len,
							signature->ptr, &sig_len, &this->key, &rng);
		wc_FreeRng(&rng);
	}
	pqc_params_free(&pqc_params);

	if (ret != 0)
	{
		chunk_free(signature);
		return FALSE;
	}
	return TRUE;
}

METHOD(private_key_t, decrypt, bool,
	private_private_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "ML-DSA private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_private_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->type);
}

METHOD(private_key_t, get_type, key_type_t,
	private_private_key_t *this)
{
	return this->type;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_private_key_t *this)
{
	public_key_t *public_key;
	chunk_t pubkey;
	int len;

	len = get_public_key_size(this->type);
	pubkey = chunk_alloc(len);

	if (wc_dilithium_export_public(&this->key, pubkey.ptr, &len) != 0)
	{
		chunk_free(&pubkey);
		return NULL;
	}

	public_key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
									BUILD_BLOB, pubkey, BUILD_END);
	chunk_free(&pubkey);

	return public_key;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,	chunk_t *fp)
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

METHOD(private_key_t, get_encoding, bool,
	private_private_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;
			int oid = key_type_to_oid(this->type);

			*encoding = asn1_wrap(ASN1_SEQUENCE, "cmm",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(oid),
							asn1_wrap(ASN1_OCTET_STRING, "m",
								asn1_simple_object(ASN1_CONTEXT_S_0,
												   this->keyseed))
						);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}

			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(private_key_t, destroy, void,
	private_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		wc_dilithium_free(&this->key);
		chunk_clear(&this->keyseed);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_private_key_t *create_instance(key_type_t type, uint8_t level,
											  chunk_t keyseed)
{
	private_private_key_t *this;

	INIT(this,
		.public = {
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
		.type = type,
		.keyseed = keyseed,
		.ref = 1,
	);

	if (wc_dilithium_init(&this->key) != 0 ||
		wc_dilithium_set_level(&this->key, level) != 0)
	{
		destroy(this);
		return NULL;
	}

	/* derive private and public key from seed */
	if (wc_dilithium_make_key_from_seed(&this->key, keyseed.ptr) != 0)
	{
		DBG1(DBG_LIB, "deriving %N from seed failed", key_type_names, type);
		destroy(this);
		return NULL;
	}

	return this;
}

/*
 * Described in header
 */
private_key_t *wolfssl_ml_dsa_private_key_gen(key_type_t type, va_list args)
{
	private_private_key_t *this;
	WC_RNG rng;
	chunk_t seed;
	uint8_t level = 0;
	int ret;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* just ignore the key size */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!wolfssl_ml_dsa_enabled(type, &level))
	{
		return NULL;
	}

	if (wc_InitRng(&rng) != 0)
	{
		DBG1(DBG_LIB, "initializing random generator failed");
		return NULL;
	}

	seed = chunk_alloc(DILITHIUM_SEED_SZ);
	ret = wc_RNG_GenerateBlock(&rng, seed.ptr, seed.len);
	wc_FreeRng(&rng);

	if (ret != 0)
	{
		DBG1(DBG_LIB, "generating random seed failed");
		chunk_free(&seed);
		return NULL;
	}

	this = create_instance(type, level, seed);
	if (!this)
	{
		return NULL;
	}

	return &this->public;
}

/*
 * Described in header
 */
private_key_t *wolfssl_ml_dsa_private_key_load(key_type_t type, va_list args)
{
	private_private_key_t *this;
	chunk_t priv = chunk_empty;
	uint8_t level = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				priv = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (priv.len == 0 || !wolfssl_ml_dsa_enabled(type, &level))
	{
		return NULL;
	}

	if (priv.len == DILITHIUM_SEED_SZ + 2 &&
		priv.ptr[0] == 0x80 && priv.ptr[1] == DILITHIUM_SEED_SZ)
	{
		priv = chunk_skip(priv, 2);
	}
if (priv.len != DILITHIUM_SEED_SZ)
	{
		DBG1(DBG_LIB, "error: the size of the loaded ML-DSA private key seed "
			 "is %u bytes instead of %d bytes", priv.len, DILITHIUM_SEED_SZ);

		return NULL;
	}

	this = create_instance(type, level, chunk_clone(priv));
	if (!this)
	{
		return NULL;
	}

	return &this->public;
}
#endif /* HAVE_DILITHIUM */
