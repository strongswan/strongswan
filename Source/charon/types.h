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

#include <freeswan.h>

typedef enum status_e {
	SUCCESS,
	FAILED,
	OUT_OF_RES,
	ALREADY_DONE,
	NOT_SUPPORTED
} status_t;

typedef enum ike_sa_role_e {
	INITIATOR,
	RESPONDER
} ike_sa_role_t;

typedef struct timeval timeval_t;

typedef struct timespec timespec_t;

/**
 * Representates a IKE_SA spi
 */
typedef struct spi_s spi_t;

struct spi_s{
	u_int32_t high;
	u_int32_t low;
};

#endif /*TYPES_H_*/
