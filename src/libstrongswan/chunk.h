/*
 * Copyright (C) 2008-2009 Tobias Brunner
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
 *
 * $Id$
 */

/**
 * @defgroup chunk chunk
 * @{ @ingroup libstrongswan
 */

#ifndef CHUNK_H_
#define CHUNK_H_

#include <string.h>
#include <stdarg.h>
#include <sys/types.h>

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

#include <library.h>

/**
 * A { NULL, 0 }-chunk handy for initialization.
 */
extern chunk_t chunk_empty;

/**
 * Create a new chunk pointing to "ptr" with length "len"
 */
static inline chunk_t chunk_create(u_char *ptr, size_t len)
{
	chunk_t chunk = {ptr, len};
	return chunk;
}

/**
 * Create a clone of a chunk pointing to "ptr"
 */
chunk_t chunk_create_clone(u_char *ptr, chunk_t chunk);

/**
 * Calculate length of multiple chunks
 */
size_t chunk_length(const char *mode, ...);

/**
 * Concatenate chunks into a chunk pointing to "ptr",
 * "mode" is a string of "c" (copy) and "m" (move), which says
 * how to handle the chunks in "..."
 */
chunk_t chunk_create_cat(u_char *ptr, const char* mode, ...);

/**
 * Split up a chunk into parts, "mode" is a string of "a" (alloc),
 * "c" (copy) and "m" (move). Each letter say for the corresponding chunk if
 * it should get allocated on heap, copied into existing chunk, or the chunk
 * should point into "chunk". The length of each part is an argument before
 * each target chunk. E.g.:
 * chunk_split(chunk, "mcac", 3, &a, 7, &b, 5, &c, d.len, &d);
 */
void chunk_split(chunk_t chunk, const char *mode, ...);

/**
  * Write the binary contents of a chunk_t to a file
  */
bool chunk_write(chunk_t chunk, char *path, mode_t mask, bool force);

/**
 * Convert a chunk of data to hex encoding.
 *
 * The resulting string is '\0' terminated, but the chunk does not include
 * the '\0'. If buf is supplied, it must hold at least (chunk.len * 2 + 1).
 *
 * @param chunk			data to convert
 * @param buff			buffer to write to, NULL to malloc
 * @param uppercase		TRUE to use uppercase letters
 * @return				chunk of encoded data
 */
chunk_t chunk_to_hex(chunk_t chunk, char *buf, bool uppercase);

/**
 * Convert a hex encoded in a binary chunk.
 *
 * If buf is supplied, it must hold at least (hex.len / 2) + (hex.len % 2)
 * bytes. It is filled by the right to give correct values for short inputs.
 *
 * @param hex			hex encoded input data
 * @param buf			buffer to write decoded data, NULL to malloc
 * @return				converted data
 */
chunk_t chunk_from_hex(chunk_t hex, char *buf);

/**
 * Convert a chunk of data to its base64 encoding.
 *
 * The resulting string is '\0' terminated, but the chunk does not include
 * the '\0'. If buf is supplied, it must hold at least (chunk.len * 4 / 3 + 1).
 *
 * @param chunk			data to convert
 * @param buff			buffer to write to, NULL to malloc
 * @return				chunk of encoded data
 */
chunk_t chunk_to_base64(chunk_t chunk, char *buf);

/**
 * Convert a base64 in a binary chunk.
 *
 * If buf is supplied, it must hold at least (base64.len / 4 * 3).
 *
 * @param base64		base64 encoded input data
 * @param buf			buffer to write decoded data, NULL to malloc
 * @return				converted data
 */
chunk_t chunk_from_base64(chunk_t base64, char *buf);

/**
 * Free contents of a chunk
 */
static inline void chunk_free(chunk_t *chunk)
{
	free(chunk->ptr);
	*chunk = chunk_empty;
}

/**
 * Overwrite the contents of a chunk and free it
 */
static inline void chunk_clear(chunk_t *chunk)
{
	if (chunk->ptr)
	{
		memset(chunk->ptr, 0, chunk->len);
		chunk_free(chunk);
	}
}

/**
 * Initialize a chunk to point to buffer inspectable by sizeof()
 */
#define chunk_from_buf(str) { str, sizeof(str) }

/**
 * Initialize a chunk to point to a thing
 */
#define chunk_from_thing(thing) chunk_create((char*)&(thing), sizeof(thing))

/**
 * Allocate a chunk on the heap
 */
#define chunk_alloc(bytes) chunk_create(malloc(bytes), bytes)

/**
 * Allocate a chunk on the stack
 */
#define chunk_alloca(bytes) chunk_create(alloca(bytes), bytes)

/**
 * Clone a chunk on heap
 */
#define chunk_clone(chunk) chunk_create_clone((chunk).len ? malloc(chunk.len) : NULL, chunk)

/**
 * Clone a chunk on stack
 */
#define chunk_clonea(chunk) chunk_create_clone(alloca(chunk.len), chunk)

/**
 * Concatenate chunks into a chunk on heap
 */
#define chunk_cat(mode, ...) chunk_create_cat(malloc(chunk_length(mode, __VA_ARGS__)), mode, __VA_ARGS__)

/**
 * Concatenate chunks into a chunk on stack
 */
#define chunk_cata(mode, ...) chunk_create_cat(alloca(chunk_length(mode, __VA_ARGS__)), mode, __VA_ARGS__)

/**
 * Skip n bytes in chunk (forward pointer, shorten length)
 */
static inline chunk_t chunk_skip(chunk_t chunk, size_t bytes)
{
	if (chunk.len > bytes)
	{
		chunk.ptr += bytes;
		chunk.len -= bytes;
		return chunk;
	}
	return chunk_empty;
}

/**
 *  Compare two chunks, returns zero if a equals b
 *  or negative/positive if a is small/greater than b
 */
int chunk_compare(chunk_t a, chunk_t b);

/**
 * Compare two chunks for equality,
 * NULL chunks are never equal.
 */
static inline bool chunk_equals(chunk_t a, chunk_t b)
{
	return a.ptr != NULL  && b.ptr != NULL &&
			a.len == b.len && memeq(a.ptr, b.ptr, a.len);
}

/**
 * Computes a 32 bit hash of the given chunk.
 * Note: This hash is only intended for hash tables not for cryptographic purposes.
 */
u_int32_t chunk_hash(chunk_t chunk);

/**
 * Incremental version of chunk_hash. Use this to hash two or more chunks.
 */
u_int32_t chunk_hash_inc(chunk_t chunk, u_int32_t hash);

/**
 * printf hook function for chunk_t.
 *
 * Arguments are: 
 *    chunk_t *chunk
 * Use #-modifier to print a compact version
 */
int chunk_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					  const void *const *args);

#endif /* CHUNK_H_ @}*/
