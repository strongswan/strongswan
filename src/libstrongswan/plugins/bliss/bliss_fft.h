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
 * @defgroup bliss_fft bliss_fft
 * @{ @ingroup bliss_p
 */

#ifndef BLISS_FFT_H_
#define BLISS_FFT_H_

#include "bliss_fft_params.h"

#include <library.h>

typedef struct bliss_fft_t bliss_fft_t;

/**
 * Implements a Number Theoretic Transform (NTT) via the FFT algorithm
 */
struct bliss_fft_t {

	/**
	 * Get the size of the Number Theoretic Transform
	 *
	 * @result			Transform size
	 */
	uint16_t (*get_size)(bliss_fft_t *this);

	/**
	 * Get the prime modulus of the Number Theoretic Transform
	 *
	 * @result			Prime modulus
	 */
	uint16_t (*get_modulus)(bliss_fft_t *this);

	/**
	 * Compute the [inverse] NTT of a polynomial
	 *
	 * @param a			Coefficient of input polynomial
	 * @param b			Coefficient of output polynomial
	 * @param inverse	TRUE if the inverse NTT has to be computed
	 */
	void (*transform)(bliss_fft_t *this, uint32_t *a, uint32_t *b, bool inverse);

	/**
	 * Destroy bliss_fft_t object
	 */
	void (*destroy)(bliss_fft_t *this);
};

/**
 * Create a bliss_fft_t object for a given FFT parameter set
 *
 * @param params		FFT parameters
 */
bliss_fft_t *bliss_fft_create(bliss_fft_params_t *params);

#endif /** BLISS_FFT_H_ @}*/
