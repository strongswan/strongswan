/*
 * Copyright (C) 2008 Martin Willi
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

#include "sha1_prf.h"
#include "sha1_hasher.h"

#include <arpa/inet.h>

typedef struct private_sha1_prf_t private_sha1_prf_t;
typedef struct private_sha1_hasher_t private_sha1_hasher_t;

/**
 * Private data structure with hasing context.
 */
struct private_sha1_hasher_t {
	/**
	 * Public interface for this hasher.
	 */
	sha1_hasher_t public;

	/*
	 * State of the hasher. From sha1_hasher.c, do not change it!
	 */
	u_int32_t state[5];
    u_int32_t count[2];
    u_int8_t buffer[64];
};

/**
 * Private data structure with keyed prf context.
 */
struct private_sha1_prf_t {

	/**
	 * public prf interface
	 */
	sha1_prf_t public;

	/**
	 * internal used hasher
	 */
	private_sha1_hasher_t *hasher;
};

/**
 * From sha1_hasher.c
 */
extern void SHA1Update(private_sha1_hasher_t* this, u_int8_t *data, u_int32_t len);

/**
 * Implementation of prf_t.get_bytes.
 */
static void get_bytes(private_sha1_prf_t *this, chunk_t seed, u_int8_t *bytes)
{
	u_int32_t *hash = (u_int32_t*)bytes;

	SHA1Update(this->hasher, seed.ptr, seed.len);

	hash[0] = htonl(this->hasher->state[0]);
	hash[1] = htonl(this->hasher->state[1]);
	hash[2] = htonl(this->hasher->state[2]);
	hash[3] = htonl(this->hasher->state[3]);
	hash[4] = htonl(this->hasher->state[4]);
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_block_size(private_sha1_prf_t *this)
{
	return HASH_SIZE_SHA1;
}

/**
 * Implementation of prf_t.allocate_bytes.
 */
static void allocate_bytes(private_sha1_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	*chunk = chunk_alloc(HASH_SIZE_SHA1);
	get_bytes(this, seed, chunk->ptr);
}

/**
 * Implementation of prf_t.get_key_size.
 */
static size_t get_key_size(private_sha1_prf_t *this)
{
	return sizeof(this->hasher->state);
}

/**
 * Implementation of prf_t.set_key.
 */
static void set_key(private_sha1_prf_t *this, chunk_t key)
{
	int i, rounds;
	u_int32_t *iv = (u_int32_t*)key.ptr;

	this->hasher->public.hasher_interface.reset(&this->hasher->public.hasher_interface);
	rounds = min(key.len/sizeof(u_int32_t), sizeof(this->hasher->state));
	for (i = 0; i < rounds; i++)
	{
		this->hasher->state[i] ^= htonl(iv[i]);
	}
}

/**
 * Implementation of prf_t.destroy.
 */
static void destroy(private_sha1_prf_t *this)
{
	this->hasher->public.hasher_interface.destroy(&this->hasher->public.hasher_interface);
	free(this);
}

/**
 * see header
 */
sha1_prf_t *sha1_prf_create(pseudo_random_function_t algo)
{
	private_sha1_prf_t *this;
	if (algo != PRF_KEYED_SHA1)
	{
		return NULL;
	}
	this = malloc_thing(private_sha1_prf_t);
	this->public.prf_interface.get_bytes = (void (*) (prf_t *,chunk_t,u_int8_t*))get_bytes;
	this->public.prf_interface.allocate_bytes = (void (*) (prf_t*,chunk_t,chunk_t*))allocate_bytes;
	this->public.prf_interface.get_block_size = (size_t (*) (prf_t*))get_block_size;
	this->public.prf_interface.get_key_size = (size_t (*) (prf_t*))get_key_size;
	this->public.prf_interface.set_key = (void (*) (prf_t *,chunk_t))set_key;
	this->public.prf_interface.destroy = (void (*) (prf_t *))destroy;

	this->hasher = (private_sha1_hasher_t*)sha1_hasher_create(HASH_SHA1);

	return &this->public;
}

