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

#include "xcbc_prf.h"

#include "xcbc.h"

typedef struct private_xcbc_prf_t private_xcbc_prf_t;

/**
 * Private data of a xcbc_prf_t object.
 */
struct private_xcbc_prf_t {

	/**
	 * Public xcbc_prf_t interface.
	 */
	xcbc_prf_t public;	
	
	/**
	 * xcbc to use for generation.
	 */
	xcbc_t *xcbc;
};

/**
 * Implementation of prf_t.get_bytes.
 */
static void get_bytes(private_xcbc_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->xcbc->get_mac(this->xcbc, seed, buffer);
}

/**
 * Implementation of prf_t.allocate_bytes.
 */
static void allocate_bytes(private_xcbc_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	if (chunk)
	{
		*chunk = chunk_alloc(this->xcbc->get_block_size(this->xcbc));
		get_bytes(this, seed, chunk->ptr);
	}
	else
	{
		get_bytes(this, seed, NULL);
	}
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_block_size(private_xcbc_prf_t *this)
{
	return this->xcbc->get_block_size(this->xcbc);
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_key_size(private_xcbc_prf_t *this)
{
	/* in xcbc, block and key size are always equal */
	return this->xcbc->get_block_size(this->xcbc);
}

/**
 * Implementation of prf_t.set_key.
 */
static void set_key(private_xcbc_prf_t *this, chunk_t key)
{
	this->xcbc->set_key(this->xcbc, key);
}

/**
 * Implementation of prf_t.destroy.
 */
static void destroy(private_xcbc_prf_t *this)
{
	this->xcbc->destroy(this->xcbc);
	free(this);
}

/*
 * Described in header.
 */
xcbc_prf_t *xcbc_prf_create(pseudo_random_function_t algo)
{
	private_xcbc_prf_t *this;
	xcbc_t *xcbc;
	
	switch (algo)
	{
		case PRF_AES128_XCBC:
			xcbc = xcbc_create(ENCR_AES_CBC, 16);
			break;
		default:
			return NULL;
	}
	if (!xcbc)
	{
		return NULL;
	}
	
	this = malloc_thing(private_xcbc_prf_t);
	this->xcbc = xcbc;
	
	this->public.prf_interface.get_bytes = (void (*) (prf_t *,chunk_t,u_int8_t*))get_bytes;
	this->public.prf_interface.allocate_bytes = (void (*) (prf_t*,chunk_t,chunk_t*))allocate_bytes;
	this->public.prf_interface.get_block_size = (size_t (*) (prf_t*))get_block_size;
	this->public.prf_interface.get_key_size = (size_t (*) (prf_t*))get_key_size;
	this->public.prf_interface.set_key = (void (*) (prf_t *,chunk_t))set_key;
	this->public.prf_interface.destroy = (void (*) (prf_t *))destroy;
	
	return &this->public;
}

