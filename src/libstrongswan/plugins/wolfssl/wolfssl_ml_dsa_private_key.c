/*
 * Copyright (C) 2024 Andreas Steffen
 *
 * Copyright (C) 2019 Sean Parkinson, wolfSSL Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "wolfssl_common.h"

#if defined(HAVE_DILITHIUM)

#include "wolfssl_ml_dsa_private_key.h"

#include <utils/debug.h>

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
	 * Reference count
	 */
	refcount_t ref;
};


METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{

	return FALSE;
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
	return 0;
}

METHOD(private_key_t, get_type, key_type_t,
	private_private_key_t *this)
{
	return this->type;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_private_key_t *this)
{
	public_key_t *public = NULL;

	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return FALSE;
}

METHOD(private_key_t, get_encoding, bool,
	private_private_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	return FALSE;
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
		lib->encoding->clear_cache(lib->encoding, &this->key);
		wc_dilithium_free(&this->key);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_private_key_t *create_internal(key_type_t type, uint8_t level)
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
		.ref = 1,
	);

	if (wc_dilithium_init(&this->key) ||
		wc_dilithium_set_level(&this->key, level))
	{
    	free(this);
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
	uint8_t level = 0;

	if (type == KEY_ML_DSA_44)
	{
#ifndef WOLFSSL_NO_ML_DSA_44
		level = WC_ML_DSA_44;
#endif
	}
	else if (type == KEY_ML_DSA_65)
	{
#ifndef WOLFSSL_NO_ML_DSA_65
		level = WC_ML_DSA_65;
#endif
	}
	else if (type == KEY_ML_DSA_87)
	{
#ifndef WOLFSSL_NO_ML_DSA_87
		level = WC_ML_DSA_87;
#endif
	}
	if (level == 0)
	{
		return NULL;
	}

	this = create_internal(type, level);
	if (!this)
	{
		return NULL;
	}

	return &this->public;
}

/**
 * Fix the internal state if only the private key is set
 */
static int set_public_key(private_private_key_t *this)
{
	int ret = 0;

	return ret;
}

#define ML_DSA_SEED_SIZE	32

/*
 * Described in header
 */
private_key_t *wolfssl_ml_private_key_load(key_type_t type, va_list args)
{
	private_private_key_t *this;
	chunk_t blob = chunk_empty, priv = chunk_empty;
	uint8_t level = 0;
	int idx;
	int ret = -1;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_PRIV_ASN1_DER:
				priv = va_arg(args, chunk_t);

				/* check for ASN.1 wrapped key */
				if (priv.len != ML_DSA_SEED_SIZE + 2 ||
					priv.ptr[0] != ASN_OCTET_STRING ||
					priv.ptr[1] != ML_DSA_SEED_SIZE)
				{
					return NULL;
				}
				priv = chunk_skip(priv, 2);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (type == KEY_ML_DSA_44)
	{
#ifndef WOLFSSL_NO_ML_DSA_44
		level = WC_ML_DSA_44;
#endif
	}
	else if (type == KEY_ML_DSA_65)
	{
#ifndef WOLFSSL_NO_ML_DSA_65
		level = WC_ML_DSA_65;
#endif
	}
	else if (type == KEY_ML_DSA_87)
	{
#ifndef WOLFSSL_NO_ML_DSA_87
		level = WC_ML_DSA_87;
#endif
	}
	if (level == 0)
	{
		return NULL;
	}

	this = create_internal(type, level);
	if (!this)
	{
		return NULL;
	}
	if (priv.len)
	{
		ret = wc_dilithium_import_private_only(priv.ptr, priv.len, &this->key);
	}
	else if (blob.len)
	{
		idx = 0;
		ret = wc_Dilithium_PrivateKeyDecode(blob.ptr, &idx, &this->key, blob.len);
	}

	if (ret == 0)
	{
		ret = set_public_key(this);
	}
	if (ret != 0)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* HAVE_DILITHIUM */
