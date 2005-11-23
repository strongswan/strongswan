/**
 * @file prf_plus.c
 * 
 * @brief Implements the prf+ function described in IKEv2 draft.
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


#include "prf_plus.h"

#include <utils/allocator.h>
#include <definitions.h>

/**
 * Private data of an prf_plus_t object.
 * 
 */
typedef struct private_prf_plus_s private_prf_plus_t;

struct private_prf_plus_s {
	/**
	 * public prf_plus_t interface
	 */
	prf_plus_t public;
	
	/**
	 * prf to use
	 */
	prf_t *prf;
	
	/**
	 * initial seed
	 */
	chunk_t seed;
	
	/**
	 * buffer to store current prf result
	 */
	chunk_t buffer;
		
	/**
	 * already given out bytes in current buffer
	 */
	size_t given_out;
	
	/**
	 * octet which will be appended to the seed
	 */
	u_int8_t appending_octet;
};


/**
 * implementation of prf_plus_t.get_bytes
 */
static status_t get_bytes(private_prf_plus_t *this, size_t length, u_int8_t *buffer)
{	
	chunk_t appending_chunk;
	size_t bytes_in_round;
	size_t total_bytes_written = 0;
	
	appending_chunk.ptr = &(this->appending_octet);
	appending_chunk.len = 1;
	
	while (length > 0)
	{	/* still more to do... */
		if (this->buffer.len == this->given_out)
		{	/* no bytes left in buffer, get next*/	
			this->prf->get_bytes(this->prf, this->buffer, NULL);
			this->prf->get_bytes(this->prf, this->seed, NULL);
			this->prf->get_bytes(this->prf, appending_chunk, this->buffer.ptr);
			this->given_out = 0;
			this->appending_octet++;
		}
		/* how many bytes can we write in this round ? */
		bytes_in_round = min(length, this->buffer.len - this->given_out);
		/* copy bytes from buffer with offset */
		memcpy(buffer + total_bytes_written, this->buffer.ptr + this->given_out, bytes_in_round);
		
		length -= bytes_in_round;
		this->given_out += bytes_in_round;
		total_bytes_written += bytes_in_round;
	}
	return SUCCESS;
}

/**
 * implementation of prf_plus_t.allocate_bytes
 */	
static status_t allocate_bytes(private_prf_plus_t *this, size_t length, chunk_t *chunk)
{
	chunk->ptr = allocator_alloc(length);
	chunk->len = length;
	if (chunk->ptr == NULL)
	{
		return OUT_OF_RES;	
	}
	return this->public.get_bytes(&(this->public), length, chunk->ptr);
}

/**
 * implementation of prf_plus_t.destroy
 */
static status_t destroy(private_prf_plus_t *this)
{
	allocator_free(this->buffer.ptr);
	allocator_free(this->seed.ptr);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Description in header
 */
prf_plus_t *prf_plus_create(prf_t *prf, chunk_t seed)
{
	private_prf_plus_t *this;
	chunk_t appending_chunk;
	
	this = allocator_alloc_thing(private_prf_plus_t);
	if (this == NULL)
	{
		return NULL;	
	}
	/* set public methods */
	this->public.get_bytes = (size_t (*)(prf_plus_t *,size_t,u_int8_t*))get_bytes;
	this->public.allocate_bytes = (size_t (*)(prf_plus_t *,size_t,chunk_t*))allocate_bytes;
	this->public.destroy = (status_t (*)(prf_plus_t *))destroy;
	
	/* take over prf */
	this->prf = prf;
	
	/* allocate buffer for prf output */
	this->buffer.len = prf->get_block_size(prf);
	this->buffer.ptr = allocator_alloc(this->buffer.len);
	if (this->buffer.ptr == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	this->appending_octet = 0x01;
	
	/* clone seed */
	this->seed.ptr = allocator_clone_bytes(seed.ptr, seed.len);
	this->seed.len = seed.len;
	if (this->seed.ptr == NULL)
	{
		allocator_free(this->buffer.ptr);
		allocator_free(this);
		return NULL;	
	}
	
	/* do the first run */
	appending_chunk.ptr = &(this->appending_octet);
	appending_chunk.len = 1;
	this->prf->get_bytes(this->prf, this->seed, NULL);
	this->prf->get_bytes(this->prf, appending_chunk, this->buffer.ptr);
	this->given_out = 0;
	this->appending_octet++;
	
	return &(this->public);
}
