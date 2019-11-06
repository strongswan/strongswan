/*
 * MIT License
 *
 * Copyright (C) Microsoft Corporation
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
 * @defgroup frodo_utils frodo_utls
 * @{ @ingroup frodo_p
 */

#ifndef FRODO_UTILS_H_
#define FRODO_UTILS_H_

#include "frodo_params.h"

#include <library.h>

/**
 * Pack the input uint16 vector into a char output vector,
 * copying lsb bits from each input element.
 * If inlen * lsb / 8 > outlen, only outlen * 8 bits are copied.
 *
 * @param out
 * @param outlen
 * @param in
 * @param inlen
 * @param lsb
 */
void frodo_pack(u_char *out, size_t outlen, uint16_t *in, size_t inlen,
				u_char lsb);

/**
 * Unpack the input char vector into a uint16_t output vector,
 * copying lsb bits for each output element from input.
 * outlen must be at least ceil(inlen * 8 / lsb).
 *
 * @param out
 * @param outlen
 * @param in
 * @param inlen
 * @param lsb
 */
void frodo_unpack(uint16_t *out, size_t outlen, u_char *in, size_t inlen,
				  u_char lsb);

/**
 * Fills vector s with n samples from the noise distribution which requires
 * 16 bits to sample. The distribution is specified by its CDF.
 *
 * @param params	parameter set
 * @param s			pseudo-random values (are overwritten by output)
 * @param n 		size of s
 */
void frodo_sample_n(const frodo_params_t *params, uint16_t *s, size_t n);

/**
 * Generate-and-multiply: generate matrix A (N x N) row-wise,
 * multiply by s on the right.
 *
 * @param params	parameter set
 * @param out 		out = A*s + e (N x N_BAR)
 * @param s			array (N x N_BAR)
 * @param e			array (N x N_BAR)
 * @param seed_A	seed for matrix A
 * @param use_aes	if TRUE use AES128 for matrix A, otherwise use SHAKE128
 * @return			TRUE if successful
 */
bool frodo_mul_add_as_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *s, uint16_t *e, uint8_t *seed_A,
							 bool use_aes);

/**
 * Generate-and-multiply: generate matrix A (N x N) column-wise,
 *
 * @param params	parameter set
 * @param out 		out = s'*A + e' (N_BAR x N)
 * @param s			array (N_BAR x N)
 * @param e			array (N_BAR x N)
 * @param seed_A	seed for matrix A
 * @param use_aes	if TRUE use AES128 for matrix A, otherwise use SHAKE128
 * @return			TRUE if successful
 */
bool frodo_mul_add_sa_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *s, uint16_t *e, uint8_t *seed_A,
							 bool use_aes);

/**
 * Multiply by s on the left
 *
 * @param params	parameter set
 * @param b			array (N x N_BAR)
 * @param s			array (N_BAR x N)
 * @param e			array (N_BAR x N_BAR)
 * @param out		out = s*b + e (N_BAR x N_BAR)
 */
void frodo_mul_add_sb_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *b, uint16_t *s, uint16_t *e);

/**
 * Multiply by s on the right
 *
 * @param params	parameter set
 * @param out		out = b*s (N_BAR x N_BAR)
 * @param b			array (N_BAR x N),
 * @param s			array (N x N_BAR)
 */
 void frodo_mul_bs(const frodo_params_t *params, uint16_t *out,
 				   uint16_t *b, uint16_t *s);

/**
 * Add a and b
 *
 * @param params	parameter set
 * @param out		c = a + b (N_BAR x N_AR)
 * @param a			array (N_BAR x N_BAR)
 * @param b			array (N_BAR x N_BAR)
 */
void frodo_add(const frodo_params_t *params, uint16_t *out,
			   uint16_t *a, uint16_t *b);

/**
 * Subtract a and b
 *
 * @param params	parameter set
 * @param out		c = a - b (N_BAR x N_AR)
 * @param a			array (N_BAR x N_BAR)
 * @param b			array (N_BAR x N_BAR)
 */
void frodo_sub(const frodo_params_t *params, uint16_t *out,
			   uint16_t *a, uint16_t *b);

/**
 * Encode
 *
 * @param params	parameter set
 * @param out		encoded key
 * @param in		key to be encoded
 */
void frodo_key_encode(const frodo_params_t *params, uint16_t *out, uint16_t *in);

/**
 * Decode
 *
 * @param params	parameter set
 * @param out		decoded key
 * @param in		key to be decoded
 */
void frodo_key_decode(const frodo_params_t *params, uint16_t *out, uint16_t *in);

#endif /** FRODO_UTILS_H_ @}*/
