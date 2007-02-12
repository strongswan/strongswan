/**
 * @file fips_prf.h
 * 
 * @brief Interface of fips_prf_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef FIPS_PRF_H_
#define FIPS_PRF_H_

typedef struct fips_prf_t fips_prf_t;

#include <library.h>
#include <crypto/prfs/prf.h>
#include <crypto/hashers/hasher.h>

/**
 * @brief Implementation of prf_t using the FIPS 186-2-change1 standard.
 *
 * FIPS defines a "General Purpose Random Number Generator" (Revised
 * Algorithm for Computing m values of x (Appendix 3.1 of FIPS 186-2)). This
 * implementation is not intended for private key generation and therefore does
 * not include the "mod q" operation (see FIPS 186-2-change1 p74).
 * The FIPS PRF is stateful; the key changes every time when bytes are acquired.
 *
 * @b Constructors:
 *  - fips_prf_create()
 *  - prf_create() using one of the FIPS algorithms
 * 
 * @ingroup prfs
 */
struct fips_prf_t {
	
	/**
	 * Generic prf_t interface for this fips_prf_t class.
	 */
	prf_t prf_interface;
};

/**
 * @brief Creates a new fips_prf_t object.
 * 
 * FIPS 186-2 defines G() functions used in the PRF function. It can
 * be implemented either based on SHA1 or DES.
 *
 * @param b		size of b (in bytes, not bits)
 * @param g		G() function to use (e.g. g_sha1)
 * @return
 *				- fips_prf_t object
 *				- NULL if b invalid not supported
 * 
 * @ingroup prfs
 */
fips_prf_t *fips_prf_create(size_t b, void(*g)(u_int8_t[],chunk_t,u_int8_t[]));

/**
 * @brief Implementation of the G() function based on SHA1.
 *
 * @param t		initialization vector for SHA1 hasher, 20 bytes long
 * @param c		value to hash, not longer than 512 bit
 * @param res	result of G(), requries 20 bytes
 */
void g_sha1(u_int8_t t[], chunk_t c, u_int8_t res[]);

#endif /* FIPS_PRF_H_ */
