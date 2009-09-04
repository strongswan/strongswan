/*
 * Copyright (C) 2008 Thomas Kallenberg
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

#include <string.h>
#include <arpa/inet.h>
#include <byteswap.h>

#include "padlock_sha1_hasher.h"

#define PADLOCK_ALIGN __attribute__ ((__aligned__(16)))

typedef struct private_padlock_sha1_hasher_t private_padlock_sha1_hasher_t;

/**
 * Private data structure with hasing context.
 */
struct private_padlock_sha1_hasher_t {
	/**
	 * Public interface for this hasher.
	 */
	padlock_sha1_hasher_t public;

	/**
	 * data collected to hash
	 */
	chunk_t data;
};

/**
 * Invoke the actual padlock sha1() operation
 */
static void padlock_sha1(int len, u_char *in, u_char *out)
{
	/* rep xsha1 */
    asm volatile (
		".byte 0xf3, 0x0f, 0xa6, 0xc8"
		: "+S"(in), "+D"(out)
		: "c"(len), "a"(0));
}

/**
 * sha1() a buffer of data into digest
 */
static void sha1(chunk_t data, u_int32_t *digest)
{
	u_int32_t hash[128] PADLOCK_ALIGN;

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;

	padlock_sha1(data.len, data.ptr, (u_char*)hash);

	digest[0] = bswap_32(hash[0]);
	digest[1] = bswap_32(hash[1]);
	digest[2] = bswap_32(hash[2]);
	digest[3] = bswap_32(hash[3]);
	digest[4] = bswap_32(hash[4]);
}

/**
 * append data to the to-be-hashed buffer
 */
static void append_data(private_padlock_sha1_hasher_t *this, chunk_t data)
{
	this->data.ptr = realloc(this->data.ptr, this->data.len + data.len);
	memcpy(this->data.ptr + this->data.len, data.ptr, data.len);
	this->data.len += data.len;
}

/**
 * Implementation of hasher_t.reset.
 */
static void reset(private_padlock_sha1_hasher_t *this)
{
	chunk_free(&this->data);
}

/**
 * Implementation of hasher_t.get_hash.
 */
static void get_hash(private_padlock_sha1_hasher_t *this, chunk_t chunk,
					 u_int8_t *hash)
{
	if (hash)
	{
		if (this->data.len)
		{
			append_data(this, chunk);
			sha1(this->data, (u_int32_t*)hash);
		}
		else
		{   /* hash directly if no previous data found */
			sha1(chunk, (u_int32_t*)hash);
		}
		reset(this);
	}
	else
	{
		append_data(this, chunk);
	}
}

/**
 * Implementation of hasher_t.allocate_hash.
 */
static void allocate_hash(private_padlock_sha1_hasher_t *this, chunk_t chunk,
						  chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(HASH_SIZE_SHA1);
		get_hash(this, chunk, hash->ptr);
	}
	else
	{
		get_hash(this, chunk, NULL);
	}
}

/**
 * Implementation of hasher_t.get_hash_size.
 */
static size_t get_hash_size(private_padlock_sha1_hasher_t *this)
{
	return HASH_SIZE_SHA1;
}

/**
 * Implementation of hasher_t.destroy.
 */
static void destroy(private_padlock_sha1_hasher_t *this)
{
	free(this->data.ptr);
	free(this);
}

/*
 * Described in header.
 */
padlock_sha1_hasher_t *padlock_sha1_hasher_create(hash_algorithm_t algo)
{
	private_padlock_sha1_hasher_t *this;

	if (algo != HASH_SHA1)
	{
		return NULL;
	}

	this = malloc_thing(private_padlock_sha1_hasher_t);
	this->public.hasher_interface.get_hash = (void (*) (hasher_t*, chunk_t, u_int8_t*))get_hash;
	this->public.hasher_interface.allocate_hash = (void (*) (hasher_t*, chunk_t, chunk_t*))allocate_hash;
	this->public.hasher_interface.get_hash_size = (size_t (*) (hasher_t*))get_hash_size;
	this->public.hasher_interface.reset = (void (*) (hasher_t*))reset;
	this->public.hasher_interface.destroy = (void (*) (hasher_t*))destroy;

	this->data = chunk_empty;

	return &(this->public);
}
