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

#include "openssl_hmac_signer.h"

typedef struct private_openssl_hmac_signer_t private_openssl_hmac_signer_t;

/**
 * Private data of openssl_hmac_signer_t
 */
struct private_openssl_hmac_signer_t {

	/**
	 * Public part of this class.
	 */
	openssl_hmac_signer_t public;

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

	/**
	 * Signature truncation length
	 */
	size_t trunc;
};

METHOD(signer_t, get_block_size, size_t,
	private_openssl_hmac_signer_t *this)
{
	return this->trunc;
}

METHOD(signer_t, get_key_size, size_t,
	private_openssl_hmac_signer_t *this)
{
	return this->key.len;
}

/**
 * Resets HMAC context
 */
static void reset(private_openssl_hmac_signer_t *this)
{
	HMAC_Init_ex(&this->hmac, this->key.ptr, this->key.len, this->hasher, NULL);
}

static void get_bytes(private_openssl_hmac_signer_t *this, chunk_t seed,
					  u_int8_t *out)
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

METHOD(signer_t, get_signature, void,
	private_openssl_hmac_signer_t *this, chunk_t seed, u_int8_t *out)
{
	if (out == NULL)
	{
		get_bytes(this, seed, NULL);
	}
	else
	{
		u_int8_t mac[this->key.len];

		get_bytes(this, seed, mac);
		memcpy(out, mac, this->trunc);
	}
}

METHOD(signer_t, allocate_signature,void,
	private_openssl_hmac_signer_t *this, chunk_t seed, chunk_t *out)
{
	if (out == NULL)
	{
		get_bytes(this, seed, NULL);
	}
	else
	{
		u_int8_t mac[this->key.len];

		get_bytes(this, seed, mac);
		*out = chunk_alloc(this->trunc);
		memcpy(out->ptr, mac, this->trunc);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_openssl_hmac_signer_t *this, chunk_t seed, chunk_t signature)
{
	u_int8_t mac[this->key.len];

	get_bytes(this, seed, mac);

	if (signature.len != this->trunc)
	{
		return FALSE;
	}
	return memeq(signature.ptr, mac, this->trunc);
}

METHOD(signer_t, set_key, void,
	private_openssl_hmac_signer_t *this, chunk_t key)
{
	chunk_clear(&this->key);
	this->key = chunk_clone(key);
	reset(this);
}

METHOD(signer_t, destroy, void,
	private_openssl_hmac_signer_t *this)
{
	HMAC_CTX_cleanup(&this->hmac);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
openssl_hmac_signer_t *openssl_hmac_signer_create(integrity_algorithm_t algo)
{
	private_openssl_hmac_signer_t *this;

	INIT(this,
		.public = {
			.signer = {
				.get_signature = _get_signature,
				.allocate_signature = _allocate_signature,
				.verify_signature = _verify_signature,
				.get_block_size = _get_block_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
	);

	switch (algo)
	{
		case AUTH_HMAC_MD5_96:
			this->hasher = EVP_get_digestbyname("md5");
			this->key.len = 16;
			this->trunc = 12;
			break;
		case AUTH_HMAC_MD5_128:
			this->hasher = EVP_get_digestbyname("md5");
			this->key.len = 16;
			this->trunc = 16;
			break;
		case AUTH_HMAC_SHA1_96:
			this->hasher = EVP_get_digestbyname("sha1");
			this->key.len = 20;
			this->trunc = 12;
			break;
		case AUTH_HMAC_SHA1_128:
			this->hasher = EVP_get_digestbyname("sha1");
			this->key.len = 20;
			this->trunc = 16;
			break;
		case AUTH_HMAC_SHA1_160:
			this->hasher = EVP_get_digestbyname("sha1");
			this->key.len = 20;
			this->trunc = 20;
			break;
		case AUTH_HMAC_SHA2_256_128:
			this->hasher = EVP_get_digestbyname("sha256");
			this->key.len = 32;
			this->trunc = 16;
			break;
		case AUTH_HMAC_SHA2_256_256:
			this->hasher = EVP_get_digestbyname("sha256");
			this->key.len = 32;
			this->trunc = 32;
			break;
		case AUTH_HMAC_SHA2_384_192:
			this->hasher = EVP_get_digestbyname("sha384");
			this->key.len = 48;
			this->trunc = 24;
			break;
		case AUTH_HMAC_SHA2_384_384:
			this->hasher = EVP_get_digestbyname("sha384");
			this->key.len = 48;
			this->trunc = 48;
			break;
		case AUTH_HMAC_SHA2_512_256:
			this->hasher = EVP_get_digestbyname("sha512");
			this->key.len = 64;
			this->trunc = 32;
			break;
		default:
			break;
	}

	if (!this->hasher)
	{
		/* hash is not available */
		free(this);
		return NULL;
	}

	HMAC_CTX_init(&this->hmac);

	return &this->public;
}
