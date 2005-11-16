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

#include <sys/types.h>
#include <stdlib.h>

typedef enum status_e {
	SUCCESS,
	FAILED,
	OUT_OF_RES,
	ALREADY_DONE,
	NOT_SUPPORTED,
	INVALID_ARG,
	NOT_FOUND,
	PARSE_ERROR,
	INVALID_STATE
} status_t;


typedef struct timeval timeval_t;

typedef struct timespec timespec_t;

typedef struct sockaddr sockaddr_t;

/**
 * General purpose pointer/length abstraction
 */
typedef struct chunk_s chunk_t;
struct chunk_s {
    u_char *ptr;
    size_t len;
};

/**
 * General purpose boolean type
 */
typedef int bool;
#define FALSE	0
#define TRUE		1


#endif /*TYPES_H_*/
