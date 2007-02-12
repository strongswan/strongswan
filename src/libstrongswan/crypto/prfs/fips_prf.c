/**
 * @file fips_prf.c
 * 
 * @brief Implementation for fips_prf_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "fips_prf.h"

#include <arpa/inet.h>

#include <debug.h>

typedef struct private_fips_prf_t private_fips_prf_t;

/**
 * Private data of a fips_prf_t object.
 */
struct private_fips_prf_t {
	/**
	 * Public fips_prf_t interface.
	 */
	fips_prf_t public;
	
	/**
	 * key of prf function, "b" long
	 */
	u_int8_t *key;
	
	/**
	 * size of "b" in bytes
	 */
	size_t b;
	
	/**
	 * G function, either SHA1 or DES
	 */
	void (*g)(u_int8_t t[], chunk_t c, u_int8_t res[]);
};

/**
 * t used in G(), equals to initial SHA1 value
 */
static u_int8_t t[] = {
	0x67,0x45,0x23,0x01,0xEF,0xCD,0xAB,0x89,0x98,0xBA,
	0xDC,0xFE,0x10,0x32,0x54,0x76,0xC3,0xD2,0xE1,0xF0,
};

/**
 * sum = (a + b) mod 2 ^ (length * 8)
 */
static void add_mod(size_t length, u_int8_t a[], u_int8_t b[], u_int8_t sum[])
{
	int i;
	
	for(i = length - 1; i >= 0; i--)
	{
		u_int32_t tmp;
		int c = 0;
		
		tmp = a[i] + b[i] + c;
		sum[i] = 0xff & tmp;
		c = tmp >> 8;
	}
}

/**
 * calculate "chunk mod 2^(length*8)" and save it into buffer
 */
static void chunk_mod(size_t length, chunk_t chunk, u_int8_t buffer[])
{
	if (chunk.len < length)
	{
		/* apply seed as least significant bits, others are zero */
		memset(buffer, 0, length - chunk.len);
		memcpy(buffer + length - chunk.len, chunk.ptr, chunk.len);
	}
	else
	{
		/* use least significant bytes from seed, as we use mod 2^b */
		memcpy(buffer, chunk.ptr + chunk.len - length, length);
	}
}

/**
 * Implementation of prf_t.get_bytes.
 *
 * Test vector:
 *
 * key:
 * 0xbd, 0x02, 0x9b, 0xbe, 0x7f, 0x51, 0x96, 0x0b,
 * 0xcf, 0x9e, 0xdb, 0x2b, 0x61, 0xf0, 0x6f, 0x0f,
 * 0xeb, 0x5a, 0x38, 0xb6
 *
 * seed:
 * 0x00
 *
 * result:
 * 0x20, 0x70, 0xb3, 0x22, 0x3d, 0xba, 0x37, 0x2f,
 * 0xde, 0x1c, 0x0f, 0xfc, 0x7b, 0x2e, 0x3b, 0x49,
 * 0x8b, 0x26, 0x06, 0x14, 0x3c, 0x6c, 0x18, 0xba,
 * 0xcb, 0x0f, 0x6c, 0x55, 0xba, 0xbb, 0x13, 0x78,
 * 0x8e, 0x20, 0xd7, 0x37, 0xa3, 0x27, 0x51, 0x16
 */
static void get_bytes(private_fips_prf_t *this, chunk_t seed, u_int8_t w[])
{
	int i;
	u_int8_t xval[this->b];
	u_int8_t xseed[this->b];
	u_int8_t *xkey = this->key;
	u_int8_t one[this->b];
	chunk_t xval_chunk = chunk_from_buf(xval);
	
	memset(one, 0, this->b);
	one[this->b - 1] = 0x01;
	
	/* 3.1 */
	chunk_mod(this->b, seed, xseed);
	
	/* 3.2 */
	for (i = 0; i < 2; i++) /* twice */
	{
		/* a. XVAL = (XKEY + XSEED j) mod 2^b */
		add_mod(this->b, xkey, xseed, xval);
		DBG3("XVAL %b", xval, this->b);
		/* b. wi = G(t, XVAL ) */
		this->g(t, xval_chunk, &w[i * this->b]);
		DBG3("w[%d] %b", i, &w[i * this->b], this->b);
		/* c. XKEY = (1 + XKEY + wi) mod 2b */
		add_mod(this->b, xkey, one, xkey);
		add_mod(this->b, xkey, &w[i * this->b], xkey);
		DBG3("XKEY %b", xkey, this->b);
	}
	
	/* 3.3 done already, mod q not used */
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_block_size(private_fips_prf_t *this)
{
	return 2 * this->b;
}
/**
 * Implementation of prf_t.allocate_bytes.
 */
static void allocate_bytes(private_fips_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	*chunk = chunk_alloc(get_block_size(this));
	get_bytes(this, seed, chunk->ptr);
}

/**
 * Implementation of prf_t.get_key_size.
 */
static size_t get_key_size(private_fips_prf_t *this)
{
	return this->b;
}

/**
 * Implementation of prf_t.set_key.
 */
static void set_key(private_fips_prf_t *this, chunk_t key)
{
	/* save key as "key mod 2^b" */
	chunk_mod(this->b, key, this->key);
}

/**
 * Implementation of the G() function based on SHA1
 */
void g_sha1(u_int8_t t[], chunk_t c, u_int8_t res[])
{
	hasher_t *hasher;
	u_int8_t buf[64];
	chunk_t state_chunk;
	u_int32_t *state, *iv, *hash;
	
	if (c.len < sizeof(buf))
	{
		/* pad c with zeros */
		memset(buf, 0, sizeof(buf));
		memcpy(buf, c.ptr, c.len);
		c.ptr = buf;
		c.len = sizeof(buf);
	}
	else
	{
		/* not more than 512 bits can be G()-ed */
		c.len = sizeof(buf);
	}
	
	/* our SHA1 hasher's state is 32-Bit integers in host order. We must
	 * convert them */
	hasher = hasher_create(HASH_SHA1);
	state_chunk = hasher->get_state(hasher);
	state = (u_int32_t*)state_chunk.ptr;
	iv = (u_int32_t*)t;
	hash = (u_int32_t*)res;
	state[0] = htonl(iv[0]);
	state[1] = htonl(iv[1]);
	state[2] = htonl(iv[2]);
	state[3] = htonl(iv[3]);
	hasher->get_hash(hasher, c, NULL);
	hash[0] = htonl(state[0]);
	hash[1] = htonl(state[1]);
	hash[2] = htonl(state[2]);
	hash[3] = htonl(state[3]);
	hash[4] = htonl(state[4]);
	hasher->destroy(hasher);
}

/**
 * Implementation of prf_t.destroy.
 */
static void destroy(private_fips_prf_t *this)
{
	free(this->key);
	free(this);
}

/*
 * Described in header.
 */
fips_prf_t *fips_prf_create(size_t b, void(*g)(u_int8_t[],chunk_t,u_int8_t[]))
{
	private_fips_prf_t *this = malloc_thing(private_fips_prf_t);
	
	this->public.prf_interface.get_bytes = (void (*) (prf_t *,chunk_t,u_int8_t*))get_bytes;
	this->public.prf_interface.allocate_bytes = (void (*) (prf_t*,chunk_t,chunk_t*))allocate_bytes;
	this->public.prf_interface.get_block_size = (size_t (*) (prf_t*))get_block_size;
	this->public.prf_interface.get_key_size = (size_t (*) (prf_t*))get_key_size;
	this->public.prf_interface.set_key = (void (*) (prf_t *,chunk_t))set_key;
	this->public.prf_interface.destroy = (void (*) (prf_t *))destroy;
	
	this->g = g;
	this->b = b;
	this->key = malloc(b);
	
	return &(this->public);
}
