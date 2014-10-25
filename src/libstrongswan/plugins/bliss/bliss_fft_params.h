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
 * @defgroup bliss_fft_params bliss_fft_params
 * @{ @ingroup bliss_p
 */

#ifndef BLISS_FFT_PARAMS_H_
#define BLISS_FFT_PARAMS_H_

#include <library.h>

typedef struct bliss_fft_params_t bliss_fft_params_t;

/**
 * Defines the parameters for an NTT computed via the FFT algorithm
 */
struct bliss_fft_params_t {

	/**
	 * Prime modulus
	 */
	uint16_t q;

	/**
	 * Size of the FFT with the condition k * n = q-1
	 */
	uint16_t n;

	/**
	 * Inverse of n mod q used for normalization of the FFT
	 */
	uint16_t n_inv;

	/**
	 * Number of FFT stages  stages = log2(n)
	 */
	uint16_t stages;

	/**
	 * FFT twiddle factors (n-th roots of unity)
	 */
	uint16_t *w;

	/**
	 * FFT bit reversal
	 */
	uint16_t *rev;

};

/**
 * FFT parameters for q = 12289 and n = 512
 */
extern bliss_fft_params_t bliss_fft_12289_512;

/**
 * FFT parameters for q = 17 and n = 8
 */
extern bliss_fft_params_t bliss_fft_17_8;

#endif /** BLISS_FFT_PARAMS_H_ @}*/
