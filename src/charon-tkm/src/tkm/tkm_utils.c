/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include "tkm_utils.h"

/* Generic variable-length sequence */
struct sequence_type {
	uint32_t size;
	byte_t data[];
};
typedef struct sequence_type sequence_type;

void sequence_to_chunk(const byte_t * const first, const uint32_t len,
		chunk_t * const chunk)
{
	*chunk = chunk_alloc(len);
	memcpy(chunk->ptr, first, len);
}

void chunk_to_sequence(const chunk_t * const chunk, void *sequence)
{
	sequence_type *seq = sequence;
	seq->size = chunk->len;
	memcpy(seq->data, chunk->ptr, seq->size);
}
