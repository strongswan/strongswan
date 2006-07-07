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

#include "types.h"


/**
 * String mappings for type status_t.
 */
mapping_t status_m[] = {
	{SUCCESS, "SUCCESS"},
	{FAILED, "FAILED"},
	{OUT_OF_RES, "OUT_OF_RES"},
	{ALREADY_DONE, "ALREADY_DONE"},
	{NOT_SUPPORTED, "NOT_SUPPORTED"},
	{INVALID_ARG, "INVALID_ARG"},
	{NOT_FOUND, "NOT_FOUND"},
	{PARSE_ERROR, "PARSE_ERROR"},
	{VERIFY_ERROR, "VERIFY_ERROR"},
	{INVALID_STATE, "INVALID_STATE"},
	{DESTROY_ME, "DESTROY_ME"},
	{MAPPING_END, NULL}
};

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
void chunk_to_hex(char *buf, size_t buflen, chunk_t chunk)
{
	bool first = TRUE;

	buflen--;  /* reserve space for null termination */

	while (chunk.len > 0 && buflen > 2)
	{
		static char hexdig[] = "0123456789abcdef";

		if (first)
		{
			first = FALSE;
		}
		else
		{
			*buf++ = ':'; buflen--;
		}
		*buf++ = hexdig[(*chunk.ptr >> 4) & 0x0f];
		*buf++ = hexdig[ *chunk.ptr++     & 0x0f];
		buflen -= 2; chunk.len--;
	}
	*buf = '\0';
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

/*
 * Names of the months used by timetoa()
 */
static const char* months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * Described in header file
 */
void timetoa(char *buf, size_t buflen, const time_t *time, bool utc)
{
	if (*time == UNDEFINED_TIME)
		snprintf(buf, buflen, "--- -- --:--:--%s----", (utc)?" UTC ":" ");
	else
	{
		struct tm *t = (utc)? gmtime(time) : localtime(time);

		snprintf(buf, buflen, "%s %02d %02d:%02d:%02d%s%04d",
				months[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
				(utc)?" UTC ":" ", t->tm_year + 1900);
	}
}

