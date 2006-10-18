/**
 * @file definitions.h
 * 
 * @brief General purpose definitions and macros.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier. (Endian stuff)
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

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

#include <stddef.h>

#define BITS_PER_BYTE 8

/**
  * Default length for various auxiliary text buffers
  */
#define BUF_LEN 512

/**
 * Macro compares two strings for equality
 */
#define streq(x,y) (strcmp(x, y) == 0)

/**
 * Macro compares two binary blobs for equality
 */
#define memeq(x,y,len) (memcmp(x, y, len) == 0)

/**
 * Macro gives back larger of two values.
 */
#define max(x,y) ((x) > (y) ? (x):(y))

/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) ((x) < (y) ? (x):(y))

/**
 * Call destructor of a object if object != NULL
 */
#define DESTROY_IF(obj) if (obj) obj->destroy(obj)

/**
 * Debug macro to follow control flow
 */
#define POS printf("%s, line %d\n", __FILE__, __LINE__)

/**
 * Macro to allocate a sized type.
 */
#define malloc_thing(thing) ((thing*)malloc(sizeof(thing)))

/**
 * Assign a function as a class method
 */
#define ASSIGN(method, function) (method = (typeof(method))function)

/**
 * printf() specifier to resolf enum names, see enum_names
 */
#define ENUM_PRINTF_SPEC 'N'

typedef struct enum_name_t enum_name_t;

/**
 * Struct to store names for enums. Use the convenience macros 
 * to define these.
 * For a single range, use:
 * ENUM(name, first, last, string1, string2, ...)
 *
 * For multiple ranges, use:
 * ENUM_BEGIN(name, first, last, string1, string2, ...)
 *   ENUM_NEXT(name, first, last, last_from_previous, string3, ...)
 *   ENUM_NEXT(name, first, last, last_from_previous, string4, ...)
 * ENUM_END(name, last_from_previous)
 */
struct enum_name_t {
	long first;
	long last;
	enum_name_t *next;
	char *names[];
};

#define ENUM_BEGIN(name, first, last, ...) static enum_name_t name##last = {first, last, NULL, { __VA_ARGS__ }}
#define ENUM_NEXT(name, first, last, prev, ...) static enum_name_t name##last = {first, last, &name##prev, { __VA_ARGS__ }}
#define ENUM_END(name, prev) enum_name_t *name = &name##prev;
#define ENUM(name, first, last, ...) ENUM_BEGIN(name, first, last, __VA_ARGS__); ENUM_END(name, last)

#endif /*DEFINITIONS_H_*/
