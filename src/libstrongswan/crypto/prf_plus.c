/**
 * @file prf_plus.c
 * 
 * @brief Implementation of prf_plus_t.
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

#include "prf_plus.h"

#include <definitions.h>

typedef struct private_prf_plus_t private_prf_plus_t;

/**
 * Private data of an prf_plus_t object.
 * 
 */
struct private_prf_plus_t {
	/**
	 * Public interface of prf_plus_t.
	 */
	prf_plus_t public;
	
	/**
	 * PRF to use.
	 */
	prf_t *prf;
	
	/**
	 * Initial seed.
	 */
	chunk_t seed;
	
	/**
	 * Buffer to store current PRF result.
	 */
	chunk_t buffer;
		
	/**
	 * Already given out bytes in current buffer.
	 */
	size_t given_out;
	
	/**
	 * Octet which will be appended to the seed.
	 */
	u_int8_t appending_octet;
};

/**
 * Implementation of prf_plus_t.get_bytes.
 */
static void get_bytes(private_prf_plus_t *this, size_t length, u_int8_t *buffer)
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
}

/**
 * Implementation of prf_plus_t.allocate_bytes.
 */	
static void allocate_bytes(private_prf_plus_t *this, size_t length, chunk_t *chunk)
{
	chunk->ptr = malloc(length);
	chunk->len = length;
	this->public.get_bytes(&(this->public), length, chunk->ptr);
}

/**
 * Implementation of prf_plus_t.destroy.
 */
static void destroy(private_prf_plus_t *this)
{
	free(this->buffer.ptr);
	free(this->seed.ptr);
	free(this);
}

/*
 * Description in header.
 */
prf_plus_t *prf_plus_create(prf_t *prf, chunk_t seed)
{
	private_prf_plus_t *this;
	chunk_t appending_chunk;
	
	this = malloc_thing(private_prf_plus_t);

	/* set public methods */
	this->public.get_bytes = (void (*)(prf_plus_t *,size_t,u_int8_t*))get_bytes;
	this->public.allocate_bytes = (void (*)(prf_plus_t *,size_t,chunk_t*))allocate_bytes;
	this->public.destroy = (void (*)(prf_plus_t *))destroy;
	
	/* take over prf */
	this->prf = prf;
	
	/* allocate buffer for prf output */
	this->buffer.len = prf->get_block_size(prf);
	this->buffer.ptr = malloc(this->buffer.len);

	this->appending_octet = 0x01;
	
	/* clone seed */
	this->seed.ptr = clalloc(seed.ptr, seed.len);
	this->seed.len = seed.len;

	/* do the first run */
	appending_chunk.ptr = &(this->appending_octet);
	appending_chunk.len = 1;
	this->prf->get_bytes(this->prf, this->seed, NULL);
	this->prf->get_bytes(this->prf, appending_chunk, this->buffer.ptr);
	this->given_out = 0;
	this->appending_octet++;
	
	return &(this->public);
}
