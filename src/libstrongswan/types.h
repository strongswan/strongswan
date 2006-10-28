/**
 * @file types.h
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
 

#ifndef TYPES_H_
#define TYPES_H_

#include <gmp.h> 
#include <sys/types.h>
#include <stdlib.h>

#include <definitions.h>

/**
 * General purpose boolean type.
 */
typedef int bool;
#define FALSE	0
#define TRUE	1

/**
 *  error message, or NULL for success
 */
typedef const char *err_t;

typedef enum status_t status_t;

/**
 * Return values of function calls.
 */
enum status_t {
	/**
	 * Call succeeded.
	 */
	SUCCESS,
	
	/**
	 * Call failed.
	 */
	FAILED,
	
	/**
	 * Out of resources.
	 */
	OUT_OF_RES,
	
	/**
	 * The suggested operation is already done
	 */
	ALREADY_DONE,
	
	/**
	 * Not supported.
	 */
	NOT_SUPPORTED,
	
	/**
	 * One of the arguments is invalid.
	 */
	INVALID_ARG,
	
	/**
	 * Something could not be found.
	 */
	NOT_FOUND,
	
	/**
	 * Error while parsing.
	 */
	PARSE_ERROR,
	
	/**
	 * Error while verifying.
	 */
	VERIFY_ERROR,
	
	/**
	 * Object in invalid state.
	 */
	INVALID_STATE,
	
	/**
	 * Destroy object which called method belongs to.
	 */
	DESTROY_ME,
};

/**
 * enum_names for type status_t.
 */
extern enum_name_t *status_names;

/**
 * Handle struct timeval like an own type.
 */
typedef struct timeval timeval_t;

/**
 * Handle struct timespec like an own type.
 */
typedef struct timespec timespec_t;

/**
 * Handle struct chunk_t like an own type.
 */
typedef struct sockaddr sockaddr_t;

/**
 * Use struct chunk_t as chunk_t.
 */
typedef struct chunk_t chunk_t;

/**
 * General purpose pointer/length abstraction.
 */
struct chunk_t {
	/**
	 * Pointer to start of data
	 */
	u_char *ptr;

	/**
	 * Length of data in bytes
	 */
	size_t len;
};

/**
 * used to initialize a chunk to { NULL, 0 }.
 */
extern chunk_t CHUNK_INITIALIZER;



/**
 * Printf() hook character to dump a chunk using printf.
 * The argument supplied to printf() is a pointer to a chunk.
 * E.g. printf("chunk xy is: %B", &xy);
 */
#define CHUNK_PRINTF_SPEC 'B'

/**
 * Printf() hook character to dump a chunk using printf. 
 * Two arguments are supplied for one format string charactar, 
 * first a pointer to the buffer, and as second the length of the buffer.
 * E.g. printf("buffer xy is: %b", buffer, sizeof(buffer));
 */
#define BYTES_PRINTF_SPEC 'b'

/**
 * printf specifier for time_t, use #-modifier to print time as UTC 
 */
#define TIME_PRINTF_SPEC 'T'

/**
 * printf specifier for time_t deltas, uses two arguments
 * E.g. printf("%V", begin, end);
 */
#define TIME_DELTA_PRINTF_SPEC 'V'

/**
 * time_t for a not defined time
 */
#define UNDEFINED_TIME 0

/**
 * Initialize a chunk to a static buffer
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

/**
 * Clone a data to a newly allocated buffer
 */
void *clalloc(void *pointer, size_t size);

/**
 * Special type to count references
 */
typedef volatile u_int refcount_t;

/**
 * @brief Get a new reference.
 *
 * Increments the reference counter atomic.
 *
 * @param ref	pointer to ref counter
 */
void ref_get(refcount_t *ref);

/**
 * @brief Put back a unused reference.
 *
 * Decrements the reference counter atomic and 
 * says if more references available.
 *
 * @param ref	pointer to ref counter
 * @return		TRUE if no more references counted
 */
bool ref_put(refcount_t *ref);


#endif /*TYPES_H_*/
