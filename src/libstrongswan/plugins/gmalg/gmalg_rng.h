/*
 * Copyright (C) 2012 Aleksandr Grinberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @defgroup gmalg_rng gmalg_rng
 * @{ @ingroup gmalg_p
 */

#ifndef GMALG_RNG_H_
#define GMALG_RNG_H_

#include <library.h>

typedef struct gmalg_rng_t gmalg_rng_t;

/**
 * Implementation of random number using OpenSSL.
 */
struct gmalg_rng_t {

	/**
	 * Implements rng_t interface.
	 */
	rng_t rng;
};

/**
 * Constructor to create gmalg_rng_t.
 *
 * @param quality	quality of randomness
 * @return			gmalg_rng_t
 */
gmalg_rng_t *gmalg_rng_create(rng_quality_t quality);

#endif /** GMALG_RNG_H_ @}*/
