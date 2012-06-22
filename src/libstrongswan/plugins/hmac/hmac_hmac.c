/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "hmac_hmac.h"

#include <crypto/hmacs/hmac.h>
#include <crypto/hmacs/hmac_prf.h>
#include <crypto/hmacs/hmac_signer.h>

typedef struct private_hmac_t private_hmac_t;

/**
 * Private data of a hmac_hmac_t object.
 *
 * The variable names are the same as in the RFC.
 */
struct private_hmac_t {

	/**
	 * Implements hmac_t interface
	 */
	hmac_t public;

	/**
	 * Block size, as in RFC.
	 */
	u_int8_t b;

	/**
	 * Hash function.
	 */
	hasher_t *h;

	/**
	 * Previously xor'ed key using opad.
	 */
	chunk_t opaded_key;

	/**
	 * Previously xor'ed key using ipad.
	 */
	chunk_t ipaded_key;
};

METHOD(hmac_t, get_mac, void,
	private_hmac_t *this, chunk_t data, u_int8_t *out)
{
	/* H(K XOR opad, H(K XOR ipad, text))
	 *
	 * if out is NULL, we append text to the inner hash.
	 * else, we complete the inner and do the outer.
	 *
	 */

	u_int8_t buffer[this->h->get_hash_size(this->h)];
	chunk_t inner;

	if (out == NULL)
	{
		/* append data to inner */
		this->h->get_hash(this->h, data, NULL);
	}
	else
	{
		/* append and do outer hash */
		inner.ptr = buffer;
		inner.len = this->h->get_hash_size(this->h);

		/* complete inner */
		this->h->get_hash(this->h, data, buffer);

		/* do outer */
		this->h->get_hash(this->h, this->opaded_key, NULL);
		this->h->get_hash(this->h, inner, out);

		/* reinit for next call */
		this->h->get_hash(this->h, this->ipaded_key, NULL);
	}
}

METHOD(hmac_t, get_mac_size, size_t,
	private_hmac_t *this)
{
	return this->h->get_hash_size(this->h);
}

METHOD(hmac_t, set_key, void,
	private_hmac_t *this, chunk_t key)
{
	int i;
	u_int8_t buffer[this->b];

	memset(buffer, 0, this->b);

	if (key.len > this->b)
	{
		/* if key is too long, it will be hashed */
		this->h->get_hash(this->h, key, buffer);
	}
	else
	{
		/* if not, just copy it in our pre-padded k */
		memcpy(buffer, key.ptr, key.len);
	}

	/* apply ipad and opad to key */
	for (i = 0; i < this->b; i++)
	{
		this->ipaded_key.ptr[i] = buffer[i] ^ 0x36;
		this->opaded_key.ptr[i] = buffer[i] ^ 0x5C;
	}

	/* begin hashing of inner pad */
	this->h->reset(this->h);
	this->h->get_hash(this->h, this->ipaded_key, NULL);
}

METHOD(hmac_t, destroy, void,
	private_hmac_t *this)
{
	this->h->destroy(this->h);
	chunk_clear(&this->opaded_key);
	chunk_clear(&this->ipaded_key);
	free(this);
}

/*
 * Creates an hmac_t object
 */
static hmac_t *hmac_create(hash_algorithm_t hash_algorithm)
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

	/* set b, according to hasher */
	switch (hash_algorithm)
	{
		case HASH_SHA1:
		case HASH_MD5:
		case HASH_SHA256:
			this->b = 64;
			break;
		case HASH_SHA384:
		case HASH_SHA512:
			this->b = 128;
			break;
		default:
			free(this);
			return NULL;
	}

	this->h = lib->crypto->create_hasher(lib->crypto, hash_algorithm);
	if (this->h == NULL)
	{
		free(this);
		return NULL;
	}

	/* build ipad and opad */
	this->opaded_key.ptr = malloc(this->b);
	this->opaded_key.len = this->b;

	this->ipaded_key.ptr = malloc(this->b);
	this->ipaded_key.len = this->b;

	return &this->public;
}

/*
 * Described in header
 */
prf_t *hmac_hmac_prf_create(pseudo_random_function_t algo)
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
signer_t *hmac_hmac_signer_create(integrity_algorithm_t algo)
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
