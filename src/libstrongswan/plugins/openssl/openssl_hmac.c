/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include "openssl_hmac.h"

#include <crypto/hmacs/hmac.h>
#include <crypto/hmacs/hmac_prf.h>
#include <crypto/hmacs/hmac_signer.h>

typedef struct private_hmac_t private_hmac_t;

/**
 * Private data of a hmac_t object.
 */
struct private_hmac_t {

	/**
	 * Public interface
	 */
	hmac_t public;

	/**
	 * Hasher to use
	 */
	const EVP_MD *hasher;

	/**
	 * Current HMAC context
	 */
	HMAC_CTX hmac;

	/**
	 * Key
	 */
	chunk_t key;
};

/**
 * Resets HMAC context
 */
static void reset(private_hmac_t *this)
{
	HMAC_Init_ex(&this->hmac, this->key.ptr, this->key.len, this->hasher, NULL);
}

METHOD(hmac_t, get_mac, void,
	private_hmac_t *this, chunk_t data, u_int8_t *out)
{
	if (out == NULL)
	{
		HMAC_Update(&this->hmac, data.ptr, data.len);
	}
	else
	{
		HMAC_Update(&this->hmac, data.ptr, data.len);
		HMAC_Final(&this->hmac, out, NULL);
		reset(this);
	}
}

METHOD(hmac_t, get_mac_size, size_t,
	private_hmac_t *this)
{
	return EVP_MD_size(this->hasher);
}

METHOD(hmac_t, set_key, void,
	private_hmac_t *this, chunk_t key)
{
	chunk_clear(&this->key);
	this->key = chunk_clone(key);
	reset(this);
}

METHOD(hmac_t, destroy, void,
	private_hmac_t *this)
{
	HMAC_CTX_cleanup(&this->hmac);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Create an OpenSSL-backed implementation of the hmac_t interface
 */
static hmac_t *hmac_create(hash_algorithm_t algo)
{
	private_hmac_t *this;

	INIT(this,
		.public = {
			.get_mac = _get_mac,
			.get_mac_size = _get_mac_size,
			.set_key = _set_key,
			.destroy = _destroy,
		},
	);

	switch (algo)
	{
		case HASH_MD5:
			this->hasher = EVP_get_digestbyname("md5");
			break;
		case HASH_SHA1:
			this->hasher = EVP_get_digestbyname("sha1");
			break;
		case HASH_SHA256:
			this->hasher = EVP_get_digestbyname("sha256");
			break;
		case HASH_SHA384:
			this->hasher = EVP_get_digestbyname("sha384");
			break;
		case HASH_SHA512:
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

/*
 * Described in header
 */
prf_t *openssl_hmac_prf_create(pseudo_random_function_t algo)
{
	hmac_t *hmac = NULL;

	switch (algo)
	{
		case PRF_HMAC_SHA1:
			hmac = hmac_create(HASH_SHA1);
			break;
		case PRF_HMAC_MD5:
			hmac = hmac_create(HASH_MD5);
			break;
		case PRF_HMAC_SHA2_256:
			hmac = hmac_create(HASH_SHA256);
			break;
		case PRF_HMAC_SHA2_384:
			hmac = hmac_create(HASH_SHA384);
			break;
		case PRF_HMAC_SHA2_512:
			hmac = hmac_create(HASH_SHA512);
			break;
		default:
			break;
	}
	if (hmac)
	{
		return hmac_prf_create(hmac);
	}
	return NULL;
}

/*
 * Described in header
 */
signer_t *openssl_hmac_signer_create(integrity_algorithm_t algo)
{
	hmac_t *hmac = NULL;
	size_t trunc = 0;

	switch (algo)
	{
		case AUTH_HMAC_MD5_96:
			hmac = hmac_create(HASH_MD5);
			trunc = 12;
			break;
		case AUTH_HMAC_MD5_128:
			hmac = hmac_create(HASH_MD5);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_96:
			hmac = hmac_create(HASH_SHA1);
			trunc = 12;
			break;
		case AUTH_HMAC_SHA1_128:
			hmac = hmac_create(HASH_SHA1);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_160:
			hmac = hmac_create(HASH_SHA1);
			trunc = 20;
			break;
		case AUTH_HMAC_SHA2_256_128:
			hmac = hmac_create(HASH_SHA256);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_256_256:
			hmac = hmac_create(HASH_SHA256);
			trunc = 32;
			break;
		case AUTH_HMAC_SHA2_384_192:
			hmac = hmac_create(HASH_SHA384);
			trunc = 24;
			break;
		case AUTH_HMAC_SHA2_384_384:
			hmac = hmac_create(HASH_SHA384);
			trunc = 48;
			break;
		case AUTH_HMAC_SHA2_512_256:
			hmac = hmac_create(HASH_SHA512);
			trunc = 32;
			break;
		default:
			break;
	}
	if (hmac)
	{
		return hmac_signer_create(hmac, trunc);
	}
	return NULL;
}


