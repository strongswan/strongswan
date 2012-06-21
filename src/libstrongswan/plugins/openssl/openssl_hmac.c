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

typedef struct private_openssl_hmac_t private_openssl_hmac_t;

/**
 * Private data of a openssl_hmac_t object.
 */
struct private_openssl_hmac_t {

	/**
	 * Public interface
	 */
	openssl_hmac_t public;

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
static void reset(private_openssl_hmac_t *this)
{
	HMAC_Init_ex(&this->hmac, this->key.ptr, this->key.len, this->hasher, NULL);
}

METHOD(openssl_hmac_t, get_mac, void,
	private_openssl_hmac_t *this, chunk_t data, u_int8_t *out)
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

METHOD(openssl_hmac_t, allocate_mac, void,
	private_openssl_hmac_t *this, chunk_t data, chunk_t *out)
{
	if (out == NULL)
	{
		get_mac(this, data, NULL);
	}
	else
	{
		*out = chunk_alloc(EVP_MD_size(this->hasher));
		get_mac(this, data, out->ptr);
	}
}

METHOD(openssl_hmac_t, get_block_size, size_t,
	private_openssl_hmac_t *this)
{
	return EVP_MD_size(this->hasher);
}

METHOD(openssl_hmac_t, set_key, void,
	private_openssl_hmac_t *this, chunk_t key)
{
	chunk_clear(&this->key);
	this->key = chunk_clone(key);
	reset(this);
}

METHOD(openssl_hmac_t, destroy, void,
	private_openssl_hmac_t *this)
{
	HMAC_CTX_cleanup(&this->hmac);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
openssl_hmac_t *openssl_hmac_create(hash_algorithm_t algo)
{
	private_openssl_hmac_t *this;

	INIT(this,
		.public = {
			.get_mac = _get_mac,
			.allocate_mac = _allocate_mac,
			.get_block_size = _get_block_size,
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
