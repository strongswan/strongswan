/**
 * @file chunk.c
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

#include <stdio.h>

#include "chunk.h"

#include <printf_hook.h>

/**
 * Empty chunk.
 */
chunk_t chunk_empty = { NULL, 0 };

/**
 * Described in header.
 */
chunk_t chunk_clone(chunk_t chunk)
{
	chunk_t clone = chunk_empty;
	
	if (chunk.ptr && chunk.len > 0)
	{
		clone.ptr = malloc(chunk.len);
		clone.len = chunk.len;
		memcpy(clone.ptr, chunk.ptr, chunk.len);
	}
	
	return clone;
}

/**
 * Decribed in header.
 */
chunk_t chunk_cat(const char* mode, ...)
{
	chunk_t construct;
	va_list chunks;
	u_char *pos;
	int i;
	int count = strlen(mode);

	/* sum up lengths of individual chunks */
	va_start(chunks, mode);
	construct.len = 0;
	for (i = 0; i < count; i++)
	{
		chunk_t ch = va_arg(chunks, chunk_t);
		construct.len += ch.len;
	}
	va_end(chunks);

	/* allocate needed memory for construct */
	construct.ptr = malloc(construct.len);
	pos = construct.ptr;

	/* copy or move the chunks */
	va_start(chunks, mode);
	for (i = 0; i < count; i++)
	{
		chunk_t ch = va_arg(chunks, chunk_t);
		switch (*mode++)
		{
			case 'm':
				memcpy(pos, ch.ptr, ch.len); 
				pos += ch.len;
				free(ch.ptr);
				break;
			case 'c':
			default:
				memcpy(pos, ch.ptr, ch.len); 
				pos += ch.len;
		}
	}
	va_end(chunks);
	
	return construct;
}

/**
 * Described in header.
 */
void chunk_free(chunk_t *chunk)
{
	free(chunk->ptr);
	chunk->ptr = NULL;
	chunk->len = 0;
}

/**
 * Described in header.
 */
chunk_t chunk_alloc(size_t bytes)
{
	chunk_t new_chunk;
	new_chunk.ptr = malloc(bytes);
	new_chunk.len = bytes;
	return new_chunk;
}

/**
 * Described in header.
 */
bool chunk_equals(chunk_t a, chunk_t b)
{
	return a.ptr != NULL  && b.ptr != NULL &&
			a.len == b.len && memeq(a.ptr, b.ptr, a.len);
}

/**
 * Described in header.
 */
bool chunk_equals_or_null(chunk_t a, chunk_t b)
{
	if (a.ptr == NULL || b.ptr == NULL)
		return TRUE;
	return a.len == b.len && memeq(a.ptr, b.ptr, a.len);
}

/**
 * Number of bytes per line to dump raw data
 */
#define BYTES_PER_LINE 16

/**
 * output handler in printf() for byte ranges
 */
static int print_bytes(FILE *stream, const struct printf_info *info,
					   const void *const *args)
{
	char *bytes = *((void**)(args[0]));
	int len = *((size_t*)(args[1]));
	
	char buffer[BYTES_PER_LINE * 3];
	char ascii_buffer[BYTES_PER_LINE + 1];
	char *buffer_pos = buffer;
	char *bytes_pos  = bytes;
	char *bytes_roof = bytes + len;
	int line_start = 0;
	int i = 0;
	int written = 0;
	
	written += fprintf(stream, "=> %d bytes @ %p", len, bytes);
	
	while (bytes_pos < bytes_roof)
	{
		static char hexdig[] = "0123456789ABCDEF";
		
		*buffer_pos++ = hexdig[(*bytes_pos >> 4) & 0xF];
		*buffer_pos++ = hexdig[ *bytes_pos       & 0xF];

		ascii_buffer[i++] =
				(*bytes_pos > 31 && *bytes_pos < 127) ? *bytes_pos : '.';

		if (++bytes_pos == bytes_roof || i == BYTES_PER_LINE) 
		{
			int padding = 3 * (BYTES_PER_LINE - i);
			int written;
			
			while (padding--)
			{
				*buffer_pos++ = ' ';
			}
			*buffer_pos++ = '\0';
			ascii_buffer[i] = '\0';
			
			written += fprintf(stream, "\n%4d: %s  %s",
							   line_start, buffer, ascii_buffer);

			
			buffer_pos = buffer;
			line_start += BYTES_PER_LINE;
			i = 0;
		}
		else
		{
			*buffer_pos++ = ' ';
		}
	}
	return written;
}

/**
 * output handler in printf() for chunks
 */
static int print_chunk(FILE *stream, const struct printf_info *info,
					   const void *const *args)
{
	chunk_t *chunk = *((chunk_t**)(args[0]));
	bool first = TRUE;
	chunk_t copy = *chunk;
	int written = 0;
	
	if (!info->alt)
	{
		const void *new_args[] = {&chunk->ptr, &chunk->len};
		return print_bytes(stream, info, new_args);
	}
	
	while (copy.len > 0)
	{
		if (first)
		{
			first = FALSE;
		}
		else
		{
			written += fprintf(stream, ":");
		}
		written += fprintf(stream, "%02x", *copy.ptr++);
		copy.len--;
	}
	return written;
}

/**
 * register printf() handlers
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(PRINTF_CHUNK, print_chunk, arginfo_ptr);
	register_printf_function(PRINTF_BYTES, print_bytes, arginfo_ptr_int);
}
