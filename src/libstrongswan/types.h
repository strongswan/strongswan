/**
 * @file types.h
 * 
 * @brief Generic types.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
	 * Out of ressources.
	 */
	
	OUT_OF_RES,
	/**
	 * Already done.
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
	 * Delete object which function belongs to.
	 */
	DELETE_ME,
	
	/**
	 * An object got created.
	 */
	CREATED,
};


/**
 * String mappings for type status_t.
 */
extern mapping_t status_m[];

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
 * {NULL, 0}-chunk, handy for initialization 
 * of chunks.
 */
extern chunk_t CHUNK_INITIALIZER;

/**
 * Initialize a chunk to a static buffer
 */
#define chunk_from_buf(str) { str, sizeof(str) }

/**
 * Clone chunk contents in a newly allocated chunk
 */
chunk_t chunk_clone(chunk_t chunk);

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
 * Print a chunk in hexadecimal form
 * with each byte separated by a colon
 */
void chunk_to_hex(char *buf, size_t buflen, chunk_t chunk);

/**
 * Clone a data to a newly allocated buffer
 */
void *clalloc(void *pointer, size_t size);


#endif /*TYPES_H_*/
