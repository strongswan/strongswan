/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup ntru_test_rng ntru_test_rng
 * @{ @ingroup ntru_p
 */

#ifndef NTRU_TEST_RNG_H_
#define NTRU_TEST_RNG_H_

typedef struct ntru_test_rng_t ntru_test_rng_t;

#include <library.h>

/**
 * rng_t providing NIST SP 800-90A entropy test vectors
 */
struct ntru_test_rng_t {

	/**
	 * Implements rng_t.
	 */
	rng_t rng;
};

/**
 * Creates an ntru_test_rng_t instance.
 *
 * @param entropy	entropy test vector
 * @return			created ntru_test_rng_t
 */
rng_t *ntru_test_rng_create(chunk_t entropy);

#endif /** NTRU_TEST_RNG_H_ @} */
