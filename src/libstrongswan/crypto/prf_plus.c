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

METHOD(prf_plus_t, get_bytes, void,
	private_prf_plus_t *this, size_t length, u_int8_t *buffer)
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

METHOD(prf_plus_t, allocate_bytes, void,
	private_prf_plus_t *this, size_t length, chunk_t *chunk)
{
	if (length)
	{
		chunk->ptr = malloc(length);
		chunk->len = length;
		get_bytes(this, length, chunk->ptr);
	}
	else
	{
		*chunk = chunk_empty;
	}
}

METHOD(prf_plus_t, destroy, void,
	private_prf_plus_t *this)
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

	INIT(this,
		.public = {
			.get_bytes = _get_bytes,
			.allocate_bytes = _allocate_bytes,
			.destroy = _destroy,
		},
		.prf = prf,
	);

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
