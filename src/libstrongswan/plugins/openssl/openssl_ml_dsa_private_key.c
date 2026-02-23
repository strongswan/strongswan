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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "openssl_ml_dsa_private_key.h"
#include "openssl_util.h"

#include <utils/debug.h>

typedef struct private_private_key_t private_private_key_t;

#define ML_DSA_SEED_LEN 32

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
	EVP_PKEY *key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * reference count
	 */
	refcount_t ref;
};

/* from openssl_ml_dsa public key */
char *openssl_ml_dsa_alg_name(key_type_t type);
key_type_t openssl_ml_dsa_evp_pkey_key_type(EVP_PKEY *key);
bool openssl_ml_dsa_fingerprint(EVP_PKEY *key, cred_encoding_type_t type, chunk_t *fp);

METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	pqc_params_t pqc_params;
	OSSL_PARAM ossl_params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END};
	EVP_PKEY_CTX *ctx = NULL;
	EVP_SIGNATURE *sig_alg = NULL;
	int deterministic;
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
	deterministic = pqc_params.deterministic ? 1 : 0;
	ossl_params[0] = OSSL_PARAM_construct_int(
									OSSL_SIGNATURE_PARAM_DETERMINISTIC,
									&deterministic);
	if (pqc_params.ctx.len)
	{
		ossl_params[1] = OSSL_PARAM_construct_octet_string(
									OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
									pqc_params.ctx.ptr, pqc_params.ctx.len);
	}

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, this->key, NULL);
	if (!ctx)
	{
		goto error;
	}
	sig_alg = EVP_SIGNATURE_fetch(NULL, openssl_ml_dsa_alg_name(this->type), NULL);

	if (EVP_PKEY_sign_message_init(ctx, sig_alg, ossl_params) <= 0)
	{
		goto error;
	}

	if (EVP_PKEY_sign(ctx, NULL, &signature->len, data.ptr, data.len) <= 0)
	{
		goto error;
	}

	*signature = chunk_alloc(signature->len);

	if (EVP_PKEY_sign(ctx, signature->ptr, &signature->len,
	                  data.ptr, data.len) <= 0)
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

METHOD(private_key_t, decrypt, bool,
	private_private_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EdDSA private key decryption not implemented");
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
	public_key_t *public;
	u_char buf[2592];
	chunk_t key = {buf, sizeof(buf)};

	if (!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PUB_KEY,
										 buf, sizeof(buf), &key.len))
	{
		return NULL;
	}
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
								BUILD_BLOB, key, BUILD_END);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return openssl_ml_dsa_fingerprint(this->key, type, fingerprint);
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

			*encoding = openssl_i2chunk(PrivateKey, this->key);

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
		lib->encoding->clear_cache(lib->encoding, this->key);
		EVP_PKEY_free(this->key);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_key_t *create_internal(key_type_t type, EVP_PKEY *key)
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
		.key = key,
		.ref = 1,
	);

	return &this->public;
}

/*
 * Described in header
 */
private_key_t *openssl_ml_dsa_private_key_create(EVP_PKEY *key, bool engine)
{
	key_type_t type;

	type = openssl_ml_dsa_evp_pkey_key_type(key);
	if (type == KEY_ANY)
	{
		EVP_PKEY_free(key);
		return NULL;
	}
	return create_internal(type, key);
}

/**
 * Create an ML-DSA private_key_t instance from a seed
 */
static private_key_t *create_instance(key_type_t type, chunk_t keyseed)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, openssl_ml_dsa_alg_name(type), NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
	{
		DBG1(DBG_LIB, "failed to create ctx");
		goto end;
	}

	if (keyseed.ptr)
	{
		OSSL_PARAM params[] = {
			OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
									keyseed.ptr, keyseed.len),
			OSSL_PARAM_END
		};

		if (!EVP_PKEY_CTX_set_params(ctx, params))
		{
			DBG1(DBG_LIB, "failed to set keyseed");
			goto end;
		}
	}

	if (EVP_PKEY_generate(ctx, &key) <= 0)
	{
		DBG1(DBG_LIB, "failed to generate ML-DSA private key");
		goto end;
	}

end:
	EVP_PKEY_CTX_free(ctx);
	return key ? create_internal(type, key) : NULL;
}

/*
 * Described in header
 */
private_key_t *openssl_ml_dsa_private_key_gen(key_type_t type, va_list args)
{
	if (type != KEY_ML_DSA_44 && type != KEY_ML_DSA_65 && type != KEY_ML_DSA_87)
	{
		return NULL;
	}
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

	return create_instance(type, chunk_empty);
}

/*
 * Described in header
 */
private_key_t *openssl_ml_dsa_private_key_load(key_type_t type, va_list args)
{
	chunk_t priv = chunk_empty;

	if (type != KEY_ML_DSA_44 && type != KEY_ML_DSA_65 && type != KEY_ML_DSA_87)
	{
		return NULL;
	}

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

	if (priv.len == ML_DSA_SEED_LEN + 2 &&
		priv.ptr[0] == 0x80 && priv.ptr[1] == ML_DSA_SEED_LEN)
	{
		priv = chunk_skip(priv, 2);
	}
	if (priv.len != ML_DSA_SEED_LEN)
	{
		DBG1(DBG_LIB, "error: the size of the loaded ML-DSA private key seed "
			 "is %u bytes instead of %d bytes", priv.len, ML_DSA_SEED_LEN);
		return NULL;
	}

	return create_instance(type, priv);
}


#endif /* OPENSSL_NO_ML_DSA*/
