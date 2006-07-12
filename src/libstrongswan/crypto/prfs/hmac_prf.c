/**
 * @file hmac_prf.c
 * 
 * @brief Implementation for hmac_prf_t.
 * 
 */

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

#include "hmac_prf.h"

#include <crypto/hmac.h>


typedef struct private_hmac_prf_t private_hmac_prf_t;

/**
 * Private data of a hma_prf_t object.
 */
struct private_hmac_prf_t {
	/**
	 * Public hmac_prf_t interface.
	 */
	hmac_prf_t public;	
	
	/**
	 * Hmac to use for generation.
	 */
	hmac_t *hmac;
};

/**
 * Implementation of prf_t.get_bytes.
 */
static void get_bytes(private_hmac_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->hmac->get_mac(this->hmac, seed, buffer);
}

/**
 * Implementation of prf_t.allocate_bytes.
 */
static void allocate_bytes(private_hmac_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	this->hmac->allocate_mac(this->hmac, seed, chunk);
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_block_size(private_hmac_prf_t *this)
{
	return this->hmac->get_block_size(this->hmac);
}

/**
 * Implementation of prf_t.get_block_size.
 */
static size_t get_key_size(private_hmac_prf_t *this)
{
	/* for HMAC prfs, IKEv2 uses block size as key size */
	return this->hmac->get_block_size(this->hmac);
}

/**
 * Implementation of prf_t.set_key.
 */
static void set_key(private_hmac_prf_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

/**
 * Implementation of prf_t.destroy.
 */
static void destroy(private_hmac_prf_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header.
 */
hmac_prf_t *hmac_prf_create(hash_algorithm_t hash_algorithm)
{
	private_hmac_prf_t *this = malloc_thing(private_hmac_prf_t);
	
	this->public.prf_interface.get_bytes = (void (*) (prf_t *,chunk_t,u_int8_t*))get_bytes;
	this->public.prf_interface.allocate_bytes = (void (*) (prf_t*,chunk_t,chunk_t*))allocate_bytes;
	this->public.prf_interface.get_block_size = (size_t (*) (prf_t*))get_block_size;
	this->public.prf_interface.get_key_size = (size_t (*) (prf_t*))get_key_size;
	this->public.prf_interface.set_key = (void (*) (prf_t *,chunk_t))set_key;
	this->public.prf_interface.destroy = (void (*) (prf_t *))destroy;
	
	this->hmac = hmac_create(hash_algorithm);
	if (this->hmac == NULL)
	{
		free(this);
		return NULL;	
	}
	
	return &(this->public);
}
