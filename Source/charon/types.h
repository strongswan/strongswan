/**
 * @file types.h
 * 
 * @brief Generic type definitions
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

typedef enum status_t status_t;

/**
 * return status for function calls
 */
enum status_t {
	SUCCESS,
	FAILED,
	OUT_OF_RES,
	ALREADY_DONE,
	NOT_SUPPORTED,
	INVALID_ARG,
	NOT_FOUND,
	PARSE_ERROR,
	VERIFY_ERROR,
	INVALID_STATE,
	DELETE_ME,
	CREATED,
};

extern mapping_t status_m[];


typedef struct timeval timeval_t;

typedef struct timespec timespec_t;

typedef struct sockaddr sockaddr_t;

typedef struct chunk_t chunk_t;

/**
 * General purpose pointer/length abstraction
 */
struct chunk_t {
    u_char *ptr;
    size_t len;
};

/**
 * {NULL, 0}-chunk, handy for initialization 
 * of chunks.
 */
extern chunk_t CHUNK_INITIALIZER;

/**
 * General purpose boolean type
 */
typedef int bool;
#define FALSE	0
#define TRUE		1



#endif /*TYPES_H_*/
