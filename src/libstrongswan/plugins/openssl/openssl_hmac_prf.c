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


#include "openssl_hmac.h"
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
	 * OpenSSL based HMAC implementation
	 */
	openssl_hmac_t *hmac;
};

METHOD(prf_t, get_block_size, size_t,
	private_openssl_hmac_prf_t *this)
{
	return this->hmac->get_block_size(this->hmac);
}

METHOD(prf_t, get_key_size, size_t,
	private_openssl_hmac_prf_t *this)
{
	/* for HMAC prfs, IKEv2 uses block size as key size */
	return this->hmac->get_block_size(this->hmac);
}

METHOD(prf_t, get_bytes, void,
	private_openssl_hmac_prf_t *this, chunk_t seed, u_int8_t *out)
{
	this->hmac->get_mac(this->hmac, seed, out);
}

METHOD(prf_t, allocate_bytes, void,
	private_openssl_hmac_prf_t *this, chunk_t seed, chunk_t *out)
{
	this->hmac->allocate_mac(this->hmac, seed, out);
}

METHOD(prf_t, set_key, void,
	private_openssl_hmac_prf_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(prf_t, destroy, void,
	private_openssl_hmac_prf_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header
 */
openssl_hmac_prf_t *openssl_hmac_prf_create(pseudo_random_function_t algo)
{
	private_openssl_hmac_prf_t *this;
	openssl_hmac_t *hmac = NULL;

	switch (algo)
	{
		case PRF_HMAC_MD5:
			hmac = openssl_hmac_create(HASH_MD5);
			break;
		case PRF_HMAC_SHA1:
			hmac = openssl_hmac_create(HASH_SHA1);
			break;
		case PRF_HMAC_SHA2_256:
			hmac = openssl_hmac_create(HASH_SHA256);
			break;
		case PRF_HMAC_SHA2_384:
			hmac = openssl_hmac_create(HASH_SHA384);
			break;
		case PRF_HMAC_SHA2_512:
			hmac = openssl_hmac_create(HASH_SHA512);
			break;
		default:
			break;
	}
	if (!hmac)
	{
		return NULL;
	}

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
		.hmac = hmac,
	);

	return &this->public;
}
