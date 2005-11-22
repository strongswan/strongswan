/**
 * @file prf_hmac_sha1.h
 * 
 * @brief Implementation of prf_t interface using the
 * HMAC SHA1 algorithm. This simply wraps hmac-sha1
 * in a prf.
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

#ifndef PRF_HMAC_SHA1_H_
#define PRF_HMAC_SHA1_H_

#include "prf.h"

#include "../../types.h"

/**
 * Object representing a prf using HMAC-SHA1
 * 
 */
typedef struct prf_hmac_sha1_s prf_hmac_sha1_t;

struct prf_hmac_sha1_s {
	
	/**
	 * generic prf_t interface for this prf
	 */
	prf_t prf_interface;
};

/**
 * Creates a new prf_hmac_sha1_t object
 * 
 * @return
 * 									- prf_hmac_sha1_t if successfully
 * 									- NULL if out of ressources
 */
prf_hmac_sha1_t *prf_hmac_sha1_create();

#endif /*PRF_HMAC_SHA1_H_*/
