/**
 * @file hmac_signer.c
 * 
 * @brief Implementation of hmac_signer_t.
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

#include <string.h>

#include "hmac_signer.h"

#include <crypto/prfs/hmac_prf.h>

typedef struct private_hmac_signer_t private_hmac_signer_t;

/**
 * Private data structure with signing context.
 */
struct private_hmac_signer_t {
	/**
	 * Public interface of hmac_signer_t.
	 */
	hmac_signer_t public;
	
	/**
	 * Assigned hmac function.
	 */
	prf_t *hmac_prf;
	
	/**
	 * Block size (truncation of HMAC Hash)
	 */
	size_t block_size;
};

/**
 * Implementation of signer_t.get_signature.
 */
static void get_signature(private_hmac_signer_t *this, chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{	/* append mode */
		this->hmac_prf->get_bytes(this->hmac_prf, data, NULL);
	}
	else
	{
		u_int8_t full_mac[this->hmac_prf->get_block_size(this->hmac_prf)];
		
		this->hmac_prf->get_bytes(this->hmac_prf, data, full_mac);
		memcpy(buffer, full_mac, this->block_size);
	}
}

/**
 * Implementation of signer_t.allocate_signature.
 */
static void allocate_signature (private_hmac_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{	/* append mode */
		this->hmac_prf->get_bytes(this->hmac_prf, data, NULL);
	}
	else
	{
		chunk_t signature;
		u_int8_t full_mac[this->hmac_prf->get_block_size(this->hmac_prf)];
		
		this->hmac_prf->get_bytes(this->hmac_prf, data, full_mac);

		signature.ptr = malloc(this->block_size);
		signature.len = this->block_size;
		
		memcpy(signature.ptr, full_mac, this->block_size);

		*chunk = signature;
	}
}

/**
 * Implementation of signer_t.verify_signature.
 */
static bool verify_signature(private_hmac_signer_t *this, chunk_t data, chunk_t signature)
{
	u_int8_t full_mac[this->hmac_prf->get_block_size(this->hmac_prf)];
	
	this->hmac_prf->get_bytes(this->hmac_prf, data, full_mac);
	
	if (signature.len != this->block_size)
	{
		return FALSE;
	}
	
	/* compare mac aka signature :-) */
	if (memcmp(signature.ptr, full_mac, this->block_size) == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

/**
 * Implementation of signer_t.get_key_size.
 */
static size_t get_key_size(private_hmac_signer_t *this)
{
	/* for HMAC signer, IKEv2 uses block size as key size */
	return this->hmac_prf->get_block_size(this->hmac_prf);
}

/**
 * Implementation of signer_t.get_block_size.
 */
static size_t get_block_size(private_hmac_signer_t *this)
{
	return this->block_size;
}

/**
 * Implementation of signer_t.set_key.
 */
static void set_key(private_hmac_signer_t *this, chunk_t key)
{
	this->hmac_prf->set_key(this->hmac_prf, key);
}

/**
 * Implementation of signer_t.destroy.
 */
static status_t destroy(private_hmac_signer_t *this)
{
	this->hmac_prf->destroy(this->hmac_prf);
	free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
hmac_signer_t *hmac_signer_create(hash_algorithm_t hash_algoritm, size_t block_size)
{
	size_t hmac_block_size;
	private_hmac_signer_t *this = malloc_thing(private_hmac_signer_t);

	this->hmac_prf = (prf_t *) hmac_prf_create(hash_algoritm);
	if (this->hmac_prf == NULL)
	{
		/* algorithm not supported */
		free(this);
		return NULL;
	}
	
	/* prevent invalid truncation */
	hmac_block_size = this->hmac_prf->get_block_size(this->hmac_prf);
	this->block_size = min(block_size, hmac_block_size);
	
	/* interface functions */
	this->public.signer_interface.get_signature = (void (*) (signer_t*, chunk_t, u_int8_t*))get_signature;
	this->public.signer_interface.allocate_signature = (void (*) (signer_t*, chunk_t, chunk_t*))allocate_signature;
	this->public.signer_interface.verify_signature = (bool (*) (signer_t*, chunk_t, chunk_t))verify_signature;
	this->public.signer_interface.get_key_size = (size_t (*) (signer_t*))get_key_size;
	this->public.signer_interface.get_block_size = (size_t (*) (signer_t*))get_block_size;
	this->public.signer_interface.set_key = (void (*) (signer_t*,chunk_t))set_key;
	this->public.signer_interface.destroy = (void (*) (signer_t*))destroy;
	
	return &(this->public);
}
