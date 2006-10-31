/**
 * @file chunk.h
 *
 * @brief Pointer/lenght abstraction and its functions.
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

#ifndef CHUNK_H_
#define CHUNK_H_

#include <string.h>
#include <stdarg.h>

#include <library.h>

typedef struct chunk_t chunk_t;

/**
 * General purpose pointer/length abstraction.
 */
struct chunk_t {
	/** Pointer to start of data */
	u_char *ptr;
	/** Length of data in bytes */
	size_t len;
};

/**
 * A { NULL, 0 }-chunk handy for initialization.
 */
extern chunk_t chunk_empty;

/**
 * Initialize a chunk to point to a static(!) buffer
 */
#define chunk_from_buf(str) { str, sizeof(str) }

/**
 * Clone chunk contents in a newly allocated chunk
 */
chunk_t chunk_clone(chunk_t chunk);

/**
 * Allocate a chunk from concatenation of other chunks.
 * mode is a string 'm' and 'c, 'm' means move chunk,
 * 'c' means copy chunk.
 */
chunk_t chunk_cat(const char* mode, ...);

/**
 * Free contents of a chunk
 */
void chunk_free(chunk_t *chunk);

/**
 * Allocate a chunk
 */
chunk_t chunk_alloc(size_t bytes);

/**
 * Compare two chunks for equality,
 * NULL chunks are never equal.
 */
bool chunk_equals(chunk_t a, chunk_t b);

/**
 * Compare two chunks for equality,
 * NULL chunks are always equal.
 */
bool chunk_equals_or_null(chunk_t a, chunk_t b);

#endif /* CHUNK_H_ */
