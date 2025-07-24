/*
 * Copyright (C) 2024 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup ml_dsa_poly ml_dsa_poly
 * @{ @ingroup ml_p
 */

#ifndef ML_DSA_POLY_H_
#define ML_DSA_POLY_H_

#include "ml_dsa_params.h"

typedef struct ml_dsa_poly_t ml_dsa_poly_t;

/**
 * Represents an element in R_q = Z_q[X]/(X^n + 1) i.e. a polynomial of the
 * form f[0] + f[1]*X + ... + f[n-1]*X^n-1.
 */
struct ml_dsa_poly_t {

	/**
	 * Coefficients of the polynomial.
	 */
	int32_t f[ML_DSA_N];
};

/**
 * Computes the NTT.
 *
 * Algorithm 41 in FIPS 204.
 *
 * @param a		polynomial a (in-place NTT computation)
 */
void ml_dsa_poly_ntt(ml_dsa_poly_t *a);

/**
 * Computes the inverse NTT including scaling.
 *
 * Algorithm 42 in FIPS 204.
 *
 * @param a		polynomial a (in-place NTT computation)
 */
void ml_dsa_poly_inv_ntt(ml_dsa_poly_t *a);

/**
 * Computes the NTT of each vector element.
 *
 * @param k		vector size
 * @param a		vector of polynomials a (in-place NTT computation)
 */
void ml_dsa_poly_ntt_vec(u_int k, ml_dsa_poly_t *a);

/**
 * Computes the inverse NTT of each vector element.
 *
 * @param k		vector size
 * @param a		vector of polynomials a (in-place NTT computation)
 */
void ml_dsa_poly_inv_ntt_vec(u_int k, ml_dsa_poly_t *a);

/*
 * Copy a polynomial vector.
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 * @param b		vector of polynomials b
 */
void ml_dsa_poly_copy_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b);

/**
 * Add polynomials in vector a and b (a[i] + b[i] mod q for i in 0 to k-1).
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 * @param b		vector of polynomials b
 * @param res	vector of resulting polynomials (can be one of the others)
 */
void ml_dsa_poly_add_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						 ml_dsa_poly_t *res);

/**
 * Subtract polynomials in vector a and b (a[i] - b[i] mod q for i in 0 to k-1).
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 * @param b		vector of polynomials b
 * @param res	vector of resulting polynomials (can be one of the others)
 */
void ml_dsa_poly_sub_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						 ml_dsa_poly_t *res);

/**
 * Pointwise product of a polynomial vector b with a polynomial a.
 *
 * @param k		vector size
 * @param a		polynomial a
 * @param b		vector of polynomials b
 * @param res	result vector of polynomials
 */
void ml_dsa_poly_mult_const_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
								ml_dsa_poly_t *res);

/**
 * Dot product of two polynomial vectors a and b.
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 * @param b		vector of polynomials b
 * @param res	result polynomial
 */
void ml_dsa_poly_mult_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						  ml_dsa_poly_t *res);

/**
 * Dot product of a matrix a with a vector b.
 *
 * @param k		number of lines in matrix a and size of vector res
 * @param l		number of columns in matrix a and size of vector b
 * @param a		kxl matrix a
 * @param b		vector of polynomials b
 * @param res	result vector of polynomials
 */
void ml_dsa_poly_mult_mat(u_int k, u_int l, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						  ml_dsa_poly_t *res);

/**
 * Computes r = a mod q such that -6283008 <= r <= 6283008 ((2^31-2^22-1) mod q).
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 */
void ml_dsa_poly_reduce_vec(u_int k, ml_dsa_poly_t *a);

/**
 * Add q if coefficient is negative.
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 */
void ml_dsa_poly_cond_add_q_vec(u_int k, ml_dsa_poly_t *a);

/**
 * Decomposes a into (a1, a0) such that a ≡ a1 * 2^d + a0 mod q.
 *
 * Algorithm 35 of FIPS 204.
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 * @param a0	vector of polynomials a0
 * @param a1	vector of polynomials a1
 */
void ml_dsa_poly_power2round_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *a0,
								 ml_dsa_poly_t *a1);

/**
 * Multiply polynomial by 2^d.
 *
 * @param k		vector size
 * @param a		vector of polynomials a
 */
void ml_dsa_poly_shift_left_vec(u_int k, ml_dsa_poly_t *a);

/**
 * Decomposes a into (a1, a0) such that a ≡ a1 * (2 * gamma2) + a0 mod q.
 *
 * Algorithm 36 of FIPS 204.
 *
 * @param k			vector size
 * @param a			vector of polynomials a
 * @param a0		vector of polynomials a0
 * @param a1		vector of polynomials a1
 * @param gamma2	parameter gamma2
*/
void ml_dsa_poly_decompose_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *a0,
							   ml_dsa_poly_t *a1, int32_t gamma2);

/**
 * Return the high bits a1 of a adjusted according to hint h.
 *
 * Algorithm 40 of FIPS 204.
 *
 * @param k			vector size
 * @param a			vector of polynomials a
 * @param h			vector of polynomials h
 * @param a1		vector of polynomials a1
 * @param gamma2	parameter gamma2
*/
void ml_dsa_poly_use_hint_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *h,
							  ml_dsa_poly_t *a1, int32_t gamma2);

/**
 * Compute a hint bit indicating whether the low bits a0 of the
 * input element overflow into the high bits a1.
 *
 * Algorithm 39 in FIPS 204.
 *
 * @param k			vector size
 * @param a0		vector of polynomials containg low bits
 * @param a1		vector of polynomials containing high bits
 * @param h			vector of polynomials containing hint bits
 * @param gamma2	parameter gamma2
 * @return			total numer of hint bits
 */
u_int ml_dsa_poly_make_hint_vec(u_int k, ml_dsa_poly_t *a0, ml_dsa_poly_t *a1,
								ml_dsa_poly_t *h, int32_t gamma2);

/**
 * Check infinity norm of polynomial against given bound.
 *
 * @param a		polynomial a
 * @param bound	norm bound
 * @return		TRUE if bound is not exceeded
 */
bool ml_dsa_poly_check_bound(ml_dsa_poly_t *a, int32_t bound);

/**
 * Check infinity norm of vector of polynomials against given bound.
 *
 * @param k		vector size
 * @param a		vector if polynomials a
 * @param bound	norm bound
 * @return		TRUE if bound is not exceeded
 */
bool ml_dsa_poly_check_bound_vec(u_int k, ml_dsa_poly_t *a, int32_t bound);

#endif /** ML_DSA_POLY_H_ @}*/
