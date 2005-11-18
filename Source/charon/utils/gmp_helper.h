/**
 * @file gmp_helper.c
 * 
 * @brief Class with helper functions for gmp operations
 * 
 */

/*
 * Copyright (C) 1997 Angelos D. Keromytis.
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



#ifndef GMP_HELPER_H_
#define GMP_HELPER_H_

#include <gmp.h>

#include "../types.h"

/**
 * Class with helper functions to manipulate gmp values 
 * 
 */
typedef struct gmp_helper_s gmp_helper_t;

struct gmp_helper_s {

	/**
	 * @brief initialize an mpz_t to a random prime of specified size
	 *
	 *
	 * @param			this calling object
	 * @param[out] var 	mpz_t variable to initialize
	 * @param[in] 		bytes length of given prime in bytes
	 * @return 		
	 * 				- SUCCCESS
	 * 				- FAILED
	 * 				- OUT_OF_RES
	 */
	status_t (*init_prime) (gmp_helper_t *this, mpz_t *var, int bytes);

	/**
	 * @brief initialize an mpz_t to a random prime of specified size without using gmp 
	 * next prime function! Must be faster then the gmp version
	 *
	 *
	 * @param			this calling object
	 * @param[out] var 	mpz_t variable to initialize
	 * @param[in] 		bytes length of given prime in bytes
	 * @return 		
	 * 				- SUCCCESS
	 * 				- FAILED
	 * 				- OUT_OF_RES
	 */	
	status_t (*init_prime_fast) (gmp_helper_t *this, mpz_t *prime, int bytes);
	
	/* Convert network form (binary bytes, big-endian) to mpz_t of gmp library.
	 * 
	 * mpz_t gets initialized in this function.
	 * 
	 * @param this				calling private_gmp_helper_t object
	 * @param mpz_value 			pointer to a mpz_t value
	 * @param data				chunk_t containing the network form of data
	 */
	void (*chunk_to_mpz) (gmp_helper_t *this,mpz_t *mpz_value, chunk_t data);
	
	/* Convert mpz_t to network form (binary bytes, big-endian).
	 * 
	 * @param this				calling private_gmp_helper_t object
	 * @param mpz_value 			mpz_value to convert
	 * @param data				chunk_t where the data are written to
	 * @param bytes				number of bytes to copy 
	 * 
	 * @return					
	 * 							- SUCCESS
	 * 							- OUT_OF_RES
	 * 							- FAILED if mpz_t value was longer then given bytes count
	 */
	status_t (*mpz_to_chunk) (gmp_helper_t *this,mpz_t *mpz_value, chunk_t *data,size_t bytes);

	/**
	 * @brief Destroys an gmp_helper_t object.
	 *
	 * @param this 	gmp_helper_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (gmp_helper_t *this);
};

/**
 * Creates a new gmp_helper_t object
 * 
 * @return
 * 							- gmp_helper_t if successfully
 * 							- NULL if out of ressources
 */
gmp_helper_t *gmp_helper_create();


#endif /*GMP_HELPER_H_*/
