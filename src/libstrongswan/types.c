/**
 * @file types.c
 * 
 * @brief Generic types.
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
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <printf.h>

#include "types.h"

ENUM(status_names, SUCCESS, DESTROY_ME,
	"SUCCESS",
	"FAILED",
	"OUT_OF_RES",
	"ALREADY_DONE",
	"NOT_SUPPORTED",
	"INVALID_ARG",
	"NOT_FOUND",
	"PARSE_ERROR",
	"VERIFY_ERROR",
	"INVALID_STATE",
	"DESTROY_ME",
);


/**
 * Empty chunk.
 */
chunk_t CHUNK_INITIALIZER = { NULL, 0 };

/**
 * Described in header.
 */
chunk_t chunk_clone(chunk_t chunk)
{
	chunk_t clone = CHUNK_INITIALIZER;
	
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
 * Described in header.
 */
void *clalloc(void * pointer, size_t size)
{
	void *data;
	data = malloc(size);
	
	memcpy(data, pointer,size);
	
	return (data);
}

/**
 * We use a single mutex for all refcount variables. This
 * is not optimal for performance, but the critical section
 * is not that long...
 * TODO: Consider to include a mutex in each refcount_t variable.
 */
static pthread_mutex_t ref_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Described in header.
 * 
 * TODO: May be implemented with atomic CPU instructions
 * instead of a mutex.
 */
void ref_get(refcount_t *ref)
{
	pthread_mutex_lock(&ref_mutex);
	(*ref)++;
	pthread_mutex_unlock(&ref_mutex);
}

/**
 * Described in header.
 * 
 * TODO: May be implemented with atomic CPU instructions
 * instead of a mutex.
 */
bool ref_put(refcount_t *ref)
{
	bool more_refs;
	
	pthread_mutex_lock(&ref_mutex);
	more_refs = --(*ref);
	pthread_mutex_unlock(&ref_mutex);
	return !more_refs;
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
 * output handler in printf() for time_t
 */
static int print_time(FILE *stream, const struct printf_info *info,
				 const void *const *args)
{
	static const char* months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	time_t time = *((time_t*)(args[0]));
	bool utc = TRUE;
	struct tm t;
	
	if (info->alt)
	{
		utc = *((bool*)(args[1]));
	}
	if (time == UNDEFINED_TIME)
	{
		return fprintf(stream, "--- -- --:--:--%s----",
					   info->alt ? " UTC " : " ");
	}
	if (utc)
	{
		gmtime_r(&time, &t);
	}
	else
	{
		localtime_r(&time, &t);
	}
	return fprintf(stream, "%s %02d %02d:%02d:%02d%s%04d",
				   months[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min,
				   t.tm_sec, utc ? " UTC " : " ", t.tm_year + 1900);
}

/**
 * output handler in printf() for time deltas
 */
static int print_time_delta(FILE *stream, const struct printf_info *info,
					  const void *const *args)
{
	time_t start = *((time_t*)(args[0]));
	time_t end = *((time_t*)(args[1]));
	u_int delta = abs(end - start);
	char* unit = "second";
	
	if (delta > 2 * 60 * 60 * 24)
	{
		delta /= 60 * 60 * 24;
		unit = "days";
	}
	else if (delta > 2 * 60 * 60)
	{
		delta /= 60 * 60;
		unit = "hours";
	}
	else if (delta > 2 * 60)
	{
		delta /= 60;
		unit = "minutes";
	}
	return fprintf(stream, "%d %s", delta, unit);
}

/**
 * arginfo handler in printf() for byte ranges
 */
static int print_bytes_arginfo(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		argtypes[0] = PA_POINTER;
		argtypes[1] = PA_INT;
	}
	return 2;
}

/**
 * arginfo handler in printf() for time deltas
 */
static int print_time_delta_arginfo(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		argtypes[0] = PA_INT;
		argtypes[1] = PA_INT;
	}
	return 2;
}

/**
 * arginfo handler in printf() for time_t
 */
static int print_time_arginfo(const struct printf_info *info, size_t n, int *argtypes)
{
	if (info->alt)
	{
		if (n > 1)
		{
			argtypes[0] = PA_INT;
			argtypes[1] = PA_INT;
		}
		return 2;
	}
	
	if (n > 0)
	{
		argtypes[0] = PA_INT;
	}
	return 1;
}

/**
 * arginfo handler in printf() for chunks
 */
static int print_chunk_arginfo(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 0)
	{
		argtypes[0] = PA_POINTER;
	}
	return 1;
}

/**
 * register printf() handlers for time_t
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(CHUNK_PRINTF_SPEC, print_chunk, print_chunk_arginfo);
	register_printf_function(BYTES_PRINTF_SPEC, print_bytes, print_bytes_arginfo);
	register_printf_function(TIME_PRINTF_SPEC, print_time, print_time_arginfo);
	register_printf_function(TIME_DELTA_PRINTF_SPEC, print_time_delta, print_time_delta_arginfo);
}
