/**
 * @file prf_hmac.c
 * 
 * @brief Implementation of prf_t interface using the
 * a HMAC algorithm. This simply wraps a hmac in a prf.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "prf_hmac.h"

#include <utils/allocator.h>
#include <transforms/hmac.h>

typedef struct private_prf_hmac_s private_prf_hmac_t;

struct private_prf_hmac_s {
	/**
	 * public interface for this prf
	 */
	prf_hmac_t public;	
	
	/**
	 * hmac to use for generation
	 */
	hmac_t *hmac;
};

/**
 * implementation of prf_t.get_bytes
 */
static status_t get_bytes(private_prf_hmac_t *this, chunk_t seed, u_int8_t *buffer)
{
	return this->hmac->get_mac(this->hmac, seed, buffer);
}

/**
 * implementation of prf_t.allocate_bytes
 */
static status_t allocate_bytes(private_prf_hmac_t *this, chunk_t seed, chunk_t *chunk)
{
	return this->hmac->allocate_mac(this->hmac, seed, chunk);
}

/**
 * implementation of prf_t.get_block_size
 */
static size_t get_block_size(private_prf_hmac_t *this)
{
	return this->hmac->get_block_size(this->hmac);
}

/**
 * implementation of prf_t.set_key
 */
static status_t set_key(private_prf_hmac_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
	return SUCCESS;
}

/**
 * implementation of prf_t.destroy
 */
static status_t destroy(private_prf_hmac_t *this)
{
	allocator_free(this);
	this->hmac->destroy(this->hmac);
	return SUCCESS;
}

/*
 * Described in header
 */
prf_hmac_t *prf_hmac_create(hash_algorithm_t hash_algorithm)
{
	private_prf_hmac_t *this = allocator_alloc_thing(private_prf_hmac_t);
	
	if (this == NULL)
	{
		return NULL;	
	}
	
	this->public.prf_interface.get_bytes = (status_t (*) (prf_t *,chunk_t,u_int8_t*))get_bytes;
	this->public.prf_interface.allocate_bytes = (status_t (*) (prf_t*,chunk_t,chunk_t*))allocate_bytes;
	this->public.prf_interface.get_block_size = (size_t (*) (prf_t*))get_block_size;
	this->public.prf_interface.set_key = (status_t (*) (prf_t *,chunk_t))set_key;
	this->public.prf_interface.destroy = (status_t (*) (prf_t *))destroy;
	
	this->hmac = hmac_create(hash_algorithm);
	if (this->hmac == NULL)
	{
		allocator_free(this);
		return NULL;	
	}
	
	return &(this->public);
}
