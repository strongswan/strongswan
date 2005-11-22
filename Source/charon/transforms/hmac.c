/**
 * @file hmac.c
 * 
 * @brief Implementation of message authentication
 * using cryptographic hash functions (HMAC). See RFC2104.
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


#include "hmac.h"

#include "../utils/allocator.h"

/**
 * Private data of an hmac_t object.
 * 
 */
typedef struct private_hmac_s private_hmac_t;

struct private_hmac_s {
	/**
	 * public hmac_t interface
	 */
	hmac_t public;
	
	/**
	 * block size, as in RFC
	 */
	u_int8_t b;
	
	/**
	 * hash function
	 */
	hasher_t *h;
	
	/**
	 * previously xor'ed key using opad
	 */
	chunk_t opaded_key;
	/**
	 * previously xor'ed key using ipad
	 */
	chunk_t ipaded_key;
};

/**
 * implementation of hmac_t.get_mac
 */
static status_t get_mac(private_hmac_t *this, chunk_t data, u_int8_t *out)
{
	/* H(K XOR opad, H(K XOR ipad, text)) 
	 * 
	 * if out is NULL, we append text to the inner hash.
	 * else, we complete the inner and do the outer.
	 * 
	 */
	
	u_int8_t buffer[this->h->get_block_size(this->h)];
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
		inner.len = this->h->get_block_size(this->h);
		
		/* complete inner */
		this->h->get_hash(this->h, data, buffer);
		
		/* do outer */
		this->h->get_hash(this->h, this->opaded_key, NULL);
		this->h->get_hash(this->h, inner, out);
		
		/* reinit for next call */
		this->h->get_hash(this->h, this->ipaded_key, NULL);
	}
	return SUCCESS;
}

/**
 * implementation of hmac_t.allocate_mac
 */
static status_t allocate_mac(private_hmac_t *this, chunk_t data, chunk_t *out)
{
	/* allocate space and use get_mac */
	if (out == NULL)
	{
		/* append mode */
		this->public.get_mac(&(this->public), data, NULL);
	}
	else
	{
		out->len = this->h->get_block_size(this->h);
		out->ptr = allocator_alloc(out->len);
		if (out->ptr == NULL)
		{
			return OUT_OF_RES;	
		}
		this->public.get_mac(&(this->public), data, out->ptr);
	}
	return SUCCESS;
}
	
/**
 * implementation of hmac_t.get_block_size
 */
static size_t get_block_size(private_hmac_t *this)
{
	return this->h->get_block_size(this->h);
}

/**
 * implementation of hmac_t.set_key
 */
static status_t set_key(private_hmac_t *this, chunk_t key)
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
	
	return SUCCESS;;
}

/**
 * implementation of hmac_t.destroy
 */
static status_t destroy(private_hmac_t *this)
{
	this->h->destroy(this->h);
	allocator_free(this->opaded_key.ptr);
	allocator_free(this->ipaded_key.ptr);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
hmac_t *hmac_create(hash_algorithm_t hash_algorithm)
{
	private_hmac_t *this;
	
	this = allocator_alloc_thing(private_hmac_t);
	if (this == NULL)
	{
		return NULL;	
	}
	/* set public methods */
	this->public.get_mac = (size_t (*)(hmac_t *,chunk_t,u_int8_t*))get_mac;
	this->public.allocate_mac = (size_t (*)(hmac_t *,chunk_t,chunk_t*))allocate_mac;
	this->public.get_block_size = (size_t (*)(hmac_t *))get_block_size;
	this->public.set_key = (status_t (*)(hmac_t *,chunk_t))set_key;
	this->public.destroy = (status_t (*)(hmac_t *))destroy;
	
	/* set b, according to hasher */
	switch (hash_algorithm)
	{
		case HASH_SHA1:
			this->b = 64;
			break;
		default:
			allocator_free(this);
			return NULL;	
	}
		
	/* build the hasher */
	this->h = hasher_create(hash_algorithm);
	if (this->h == NULL)
	{
		allocator_free(this);
		return NULL;	
	}
	


	/* build ipad and opad */
	this->opaded_key.ptr = allocator_alloc(this->b);
	this->opaded_key.len = this->b;
	if (this->opaded_key.ptr == NULL)
	{
		this->h->destroy(this->h);
		allocator_free(this);
		return NULL;	
	}
	this->ipaded_key.ptr = allocator_alloc(this->b);
	this->ipaded_key.len = this->b;
	if (this->ipaded_key.ptr == NULL)
	{
		this->h->destroy(this->h);
		allocator_free(this->opaded_key.ptr);
		allocator_free(this);
		return NULL;	
	}

	
	return &(this->public);
}
