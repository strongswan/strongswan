/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup ntru_poly ntru_poly
 * @{ @ingroup ntru_p
 */

#ifndef NTRU_POLY_H_
#define NTRU_POLY_H_

typedef struct ntru_poly_t ntru_poly_t;

#include <library.h>

/**
 * Implements a trinary polynomial storing the indices of non-zero coefficients 
 */
struct ntru_poly_t {

	/**
	 * Get the size of the indices array
	 *
	 * @return			number of indices
	 */
	size_t (*get_size)(ntru_poly_t *this);

	/**
	 * @return		array containing the indices of the non-zero coefficients
	 */
	uint16_t* (*get_indices)(ntru_poly_t *this);

	/**
	 * Destroy ntru_poly_t object
	 */
	void (*destroy)(ntru_poly_t *this);
};

/**
 * Create a trits polynomial from a seed using MGF1 with a base hash function
 *
 * @param alg				hash algorithm to be used by MGF1
 * @param seed				seed used by MGF1 to generate trits from
 * @param poly_len			size of the trits polynomial
 * @param c_bits			number of bits for candidate index
 * @param limit				conversion to index limit
 * @param indices_count		number of non-zero indices
 * @param is_product_form	generate multiple polynomials
 */
ntru_poly_t *ntru_poly_create(hash_algorithm_t alg, chunk_t seed,
							  uint8_t c_bits, uint16_t limit, 
    						  uint16_t poly_len, uint32_t indices_count,
							  bool is_product_form);

#endif /** NTRU_POLY_H_ @}*/

