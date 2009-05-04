/*
 * Copyright (C) 2005-2008 Martin Willi
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
#include "hmac.h"

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
	hmac_t *hmac;
	
	/**
	 * Block size (truncation of HMAC Hash)
	 */
	size_t block_size;
};

/**
 * Implementation of signer_t.get_signature.
 */
static void get_signature(private_hmac_signer_t *this,
						  chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{	/* append mode */
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];
		
		this->hmac->get_mac(this->hmac, data, mac);
		memcpy(buffer, mac, this->block_size);
	}
}

/**
 * Implementation of signer_t.allocate_signature.
 */
static void allocate_signature (private_hmac_signer_t *this,
								chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{	/* append mode */
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];
		
		this->hmac->get_mac(this->hmac, data, mac);

		chunk->ptr = malloc(this->block_size);
		chunk->len = this->block_size;
		
		memcpy(chunk->ptr, mac, this->block_size);
	}
}

/**
 * Implementation of signer_t.verify_signature.
 */
static bool verify_signature(private_hmac_signer_t *this,
							 chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->hmac->get_block_size(this->hmac)];
	
	this->hmac->get_mac(this->hmac, data, mac);
	
	if (signature.len != this->block_size)
	{
		return FALSE;
	}
	return memeq(signature.ptr, mac, this->block_size);
}

/**
 * Implementation of signer_t.get_key_size.
 */
static size_t get_key_size(private_hmac_signer_t *this)
{
	return this->hmac->get_block_size(this->hmac);
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
	this->hmac->set_key(this->hmac, key);
}

/**
 * Implementation of signer_t.destroy.
 */
static status_t destroy(private_hmac_signer_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
hmac_signer_t *hmac_signer_create(integrity_algorithm_t algo)
{
	private_hmac_signer_t *this;
	size_t trunc;
	hash_algorithm_t hash;
	
	switch (algo)
	{
		case AUTH_HMAC_SHA1_96:
			hash = HASH_SHA1;
			trunc = 12;
			break;
		case AUTH_HMAC_SHA1_128:
			hash = HASH_SHA1;
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_160:
			hash = HASH_SHA1;
			trunc = 20;
			break;
		case AUTH_HMAC_MD5_96:
			hash = HASH_MD5;
			trunc = 12;
			break;
		case AUTH_HMAC_MD5_128:
			hash = HASH_MD5;
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_256_128:
			hash = HASH_SHA256;
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_384_192:
			hash = HASH_SHA384;
			trunc = 24;
			break;
		case AUTH_HMAC_SHA2_512_256:
			hash = HASH_SHA512;
			trunc = 32;
			break;
		default:
			return NULL;
	}
	
	this = malloc_thing(private_hmac_signer_t);
	this->hmac = hmac_create(hash);
	if (this->hmac == NULL)
	{
		free(this);
		return NULL;
	}
	/* prevent invalid truncation */
	this->block_size = min(trunc, this->hmac->get_block_size(this->hmac));
	
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

