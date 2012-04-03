/*
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

#include <string.h>

#include "hmac.h"


typedef struct private_hmac_t private_hmac_t;

/**
 * Private data of a hmac_t object.
 *
 * The variable names are the same as in the RFC.
 */
struct private_hmac_t {
	/**
	 * Public hmac_t interface.
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

METHOD(hmac_t, allocate_mac, void,
	private_hmac_t *this, chunk_t data, chunk_t *out)
{
	/* allocate space and use get_mac */
	if (out == NULL)
	{
		/* append mode */
		get_mac(this, data, NULL);
	}
	else
	{
		out->len = this->h->get_hash_size(this->h);
		out->ptr = malloc(out->len);
		get_mac(this, data, out->ptr);
	}
}

METHOD(hmac_t, get_block_size, size_t,
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
 * Described in header
 */
hmac_t *hmac_create(hash_algorithm_t hash_algorithm)
{
	private_hmac_t *this;

	INIT(this,
		.public = {
			.get_mac = _get_mac,
			.allocate_mac = _allocate_mac,
			.get_block_size = _get_block_size,
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
