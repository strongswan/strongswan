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
	 * OpenSSL based HMAC implementation
	 */
	openssl_hmac_t *hmac;

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
	return this->hmac->get_block_size(this->hmac);
}

METHOD(signer_t, get_signature, void,
	private_openssl_hmac_signer_t *this, chunk_t data, u_int8_t *out)
{
	if (out == NULL)
	{
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);
		memcpy(out, mac, this->trunc);
	}
}

METHOD(signer_t, allocate_signature,void,
	private_openssl_hmac_signer_t *this, chunk_t data, chunk_t *out)
{
	if (out == NULL)
	{
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);

		*out = chunk_alloc(this->trunc);
		memcpy(out->ptr, mac, this->trunc);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_openssl_hmac_signer_t *this, chunk_t seed, chunk_t signature)
{
	u_int8_t mac[this->hmac->get_block_size(this->hmac)];

	this->hmac->get_mac(this->hmac, seed, mac);

	if (signature.len != this->trunc)
	{
		return FALSE;
	}
	return memeq(signature.ptr, mac, this->trunc);
}

METHOD(signer_t, set_key, void,
	private_openssl_hmac_signer_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(signer_t, destroy, void,
	private_openssl_hmac_signer_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header
 */
openssl_hmac_signer_t *openssl_hmac_signer_create(integrity_algorithm_t algo)
{
	private_openssl_hmac_signer_t *this;
	openssl_hmac_t *hmac = NULL;
	size_t trunc = 0;

	switch (algo)
	{
		case AUTH_HMAC_MD5_96:
			hmac = openssl_hmac_create(HASH_MD5);
			trunc = 12;
			break;
		case AUTH_HMAC_MD5_128:
			hmac = openssl_hmac_create(HASH_MD5);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_96:
			hmac = openssl_hmac_create(HASH_SHA1);
			trunc = 12;
			break;
		case AUTH_HMAC_SHA1_128:
			hmac = openssl_hmac_create(HASH_SHA1);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_160:
			hmac = openssl_hmac_create(HASH_SHA1);
			trunc = 20;
			break;
		case AUTH_HMAC_SHA2_256_128:
			hmac = openssl_hmac_create(HASH_SHA256);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_256_256:
			hmac = openssl_hmac_create(HASH_SHA256);
			trunc = 32;
			break;
		case AUTH_HMAC_SHA2_384_192:
			hmac = openssl_hmac_create(HASH_SHA384);
			trunc = 24;
			break;
		case AUTH_HMAC_SHA2_384_384:
			hmac = openssl_hmac_create(HASH_SHA384);
			trunc = 48;
			break;
		case AUTH_HMAC_SHA2_512_256:
			hmac = openssl_hmac_create(HASH_SHA512);
			trunc = 32;
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
		.hmac = hmac,
		.trunc = trunc,
	);

	return &this->public;
}
