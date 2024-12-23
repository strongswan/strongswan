/*
 * Copyright (C) 2024 Andreas Steffen
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

#include "botan_ml_dsa_public_key.h"
#include "botan_util.h"

#include <botan/build.h>

#ifdef BOTAN_HAS_ML_DSA

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
	 * Botan public key object
	 */
	botan_pubkey_t key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Reference counter
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, get_keysize, int,
	private_public_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->type);
}

METHOD(public_key_t, verify, bool,
	private_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_ML_DSA_44:
		case SIGN_ML_DSA_65:
		case SIGN_ML_DSA_87:
			return botan_verify_signature(this->key, "Pure", data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported via botan",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt, bool,
	private_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EdDSA public key encryption not implemented");
	return FALSE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fingerprint)
{
	return botan_get_fingerprint(this->key, this, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	return botan_get_encoding(this->key, type, encoding);
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
		botan_pubkey_destroy(this->key);
		free(this);
	}
}

/**
 * Internal generic constructor
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
public_key_t *botan_ml_dsa_public_key_adopt(botan_pubkey_t key,
											key_type_t type)
{
	private_public_key_t *this;

	this = create_empty(type);
	this->key = key;

	return &this->public;
}

/**
 * Returns the Botan ML-DSA mode for a given key type
 */
 const char *botan_ml_dsa_get_mldsa_mode(key_type_t type)
 {

	switch (type)
	{
		case KEY_ML_DSA_44:
			return "ML-DSA-4x4";
		case KEY_ML_DSA_65:
			return "ML-DSA-6x5";
		case KEY_ML_DSA_87:
			return "ML-DSA-8x7";
		default:
			return NULL;
	}
}

/*
 * Described in header
 */
public_key_t *botan_ml_dsa_public_key_load(key_type_t type, va_list args)
{
	private_public_key_t *this;
	chunk_t key = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}


	this = create_empty(type);

	if (botan_pubkey_load_ml_dsa(&this->key, key.ptr, key.len,
			botan_ml_dsa_get_mldsa_mode(type)))
	{
		free(this);
		return NULL;
	}

	return &this->public;
}

#endif
