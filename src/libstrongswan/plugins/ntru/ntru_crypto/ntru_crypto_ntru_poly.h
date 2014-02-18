/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_poly.h is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File:  ntru_crypto_ntru_poly.h
 *
 * Contents: Public header file for generating and operating on polynomials
 *           in the NTRU algorithm.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_NTRU_POLY_H
#define NTRU_CRYPTO_NTRU_POLY_H


#include "ntru_crypto.h"

#include <crypto/hashers/hasher.h>


/* function declarations */

/* ntru_poly_check_min_weight
 *
 * Checks that the number of 0, +1, and -1 trinary ring elements meet or exceed
 * a minimum weight.
 */

extern bool
ntru_poly_check_min_weight(
    uint16_t  num_els,              /*  in - degree of polynomial */
    uint8_t  *ringels,              /*  in - pointer to trinary ring elements */
    uint16_t  min_wt);              /*  in - minimum weight */


/* ntru_ring_mult_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is a sparse trinary polynomial with coefficients -1, 0,
 * and 1.  It is specified by a list, bi, of its nonzero indices containing
 * indices for the bi_P1_len +1 coefficients followed by the indices for the
 * bi_M1_len -1 coefficients.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * or input array "b".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

extern void
ntru_ring_mult_indices(
    uint16_t const *a,          /*  in - pointer to ring element a */
    uint16_t        bi_P1_len,  /*  in - no. of +1 coefficients in b */
    uint16_t        bi_M1_len,  /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of N elements */
    uint16_t       *c);         /* out - address for polynomial c */


/* ntru_ring_mult_product_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is represented by the product form b1 * b2 + b3, where
 * b1, b2, and b3 are each a sparse trinary polynomial with coefficients -1,
 * 0, and 1.  It is specified by a list, bi, of the nonzero indices of b1, b2,
 * and b3, containing the indices for the +1 coefficients followed by the
 * indices for the -1 coefficients for each polynomial in that order.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * or input array "b".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

extern void
ntru_ring_mult_product_indices(
    uint16_t       *a,          /*  in - pointer to ring element a */
    uint16_t        b1i_len,    /*  in - no. of +1 or -1 coefficients in b1 */
    uint16_t        b2i_len,    /*  in - no. of +1 or -1 coefficients in b2 */
    uint16_t        b3i_len,    /*  in - no. of +1 or -1 coefficients in b3 */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of polynomials b1, b2, b3,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients for
                                         each polynomial */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of 2N elements */
    uint16_t       *c);         /* out - address for polynomial c */


/* ntru_ring_mult_coefficients
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" has coefficients in the range [0,N).
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

extern void
ntru_ring_mult_coefficients(
    uint16_t const *a,          /*  in - pointer to polynomial a */
    uint16_t const *b,          /*  in - pointer to polynomial b */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *c);         /* out - address for polynomial c */


/* ntru_ring_inv
 *
 * Finds the inverse of a polynomial, a, in (Z/2^rZ)[X]/(X^N - 1).
 *
 * This assumes q is 2^r where 8 < r < 16, so that operations mod q can
 * wait until the end, and only 16-bit arrays need to be used.
 */

extern bool
ntru_ring_inv(
    uint16_t       *a,          /*  in - pointer to polynomial a */
    uint16_t        N,          /*  in - no. of coefficients in a */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of 2N elements */
    uint16_t       *a_inv);     /* out - address for polynomial a^-1 */


#endif /* NTRU_CRYPTO_NTRU_POLY_H */
