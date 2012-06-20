/*
 * Copyright (C) 2012 Aleksandr Grinberg
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

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "openssl_hmac_prf.h"

typedef struct private_openssl_hmac_prf_t private_openssl_hmac_prf_t;

/**
 * Private data of openssl_hmac_prf_t
 */
struct private_openssl_hmac_prf_t {

	/**
	 * Public part of this class.
	 */
	openssl_hmac_prf_t public;

	/**
	 * Hasher to use
	 */
	const EVP_MD *hasher;

	/**
	 * Current HMAC context
	 */
	HMAC_CTX hmac;

	/**
	 * Key stored for reuse
	 */
	chunk_t key;
};

METHOD(prf_t, get_block_size, size_t,
	private_openssl_hmac_prf_t *this)
{
	return EVP_MD_size(this->hasher);
}

METHOD(prf_t, get_key_size, size_t,
	private_openssl_hmac_prf_t *this)
{
	/* for HMAC prfs, IKEv2 uses block size as key size */
	return EVP_MD_size(this->hasher);
}

/**
 * Resets HMAC context
 */
static void reset(private_openssl_hmac_prf_t *this)
{
	HMAC_Init_ex(&this->hmac, this->key.ptr, this->key.len, this->hasher, NULL);
}

METHOD(prf_t, get_bytes, void,
	private_openssl_hmac_prf_t *this, chunk_t seed, u_int8_t *out)
{
	if (out == NULL)
	{
		HMAC_Update(&this->hmac, seed.ptr, seed.len);
	}
	else
	{
		HMAC_Update(&this->hmac, seed.ptr, seed.len);
		HMAC_Final(&this->hmac, out, NULL);
		reset(this);
	}
}

METHOD(prf_t, allocate_bytes, void,
	private_openssl_hmac_prf_t *this, chunk_t seed, chunk_t *out)
{
	if (out == NULL)
	{
		get_bytes(this, seed, NULL);
	}
	else
	{
		*out = chunk_alloc(EVP_MD_size(this->hasher));
		get_bytes(this, seed, out->ptr);
	}
}

METHOD(prf_t, set_key, void,
	private_openssl_hmac_prf_t *this, chunk_t key)
{
	chunk_clear(&this->key);
	this->key = chunk_clone(key);
	reset(this);
}

METHOD(prf_t, destroy, void,
	private_openssl_hmac_prf_t *this)
{
	HMAC_CTX_cleanup(&this->hmac);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
openssl_hmac_prf_t *openssl_hmac_prf_create(pseudo_random_function_t algo)
{
	private_openssl_hmac_prf_t *this;

	INIT(this,
		.public = {
			.prf = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.get_block_size = _get_block_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
	);

	switch (algo)
	{
		case PRF_HMAC_MD5:
			this->hasher = EVP_get_digestbyname("md5");
			break;
		case PRF_HMAC_SHA1:
			this->hasher = EVP_get_digestbyname("sha1");
			break;
		case PRF_HMAC_SHA2_256:
			this->hasher = EVP_get_digestbyname("sha256");
			break;
		case PRF_HMAC_SHA2_384:
			this->hasher = EVP_get_digestbyname("sha384");
			break;
		case PRF_HMAC_SHA2_512:
			this->hasher = EVP_get_digestbyname("sha512");
			break;
		default:
			break;
	}

	if (!this->hasher)
	{
		free(this);
		return NULL;
	}

	HMAC_CTX_init(&this->hmac);

	return &this->public;
}
