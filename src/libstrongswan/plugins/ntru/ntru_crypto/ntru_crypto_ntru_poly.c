/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_poly.c is a component of ntru-crypto.
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
 
#include <stdlib.h>
#include <string.h>
#include "ntru_crypto_ntru_poly.h"

/* ntru_poly_check_min_weight
 *
 * Checks that the number of 0, +1, and -1 trinary ring elements meet or exceed
 * a minimum weight.
 */

bool
ntru_poly_check_min_weight(
    uint16_t  num_els,              /*  in - degree of polynomial */
    uint8_t  *ringels,              /*  in - pointer to trinary ring elements */
    uint16_t  min_wt)               /*  in - minimum weight */
{
    uint16_t wt[3];
    uint16_t i;

    wt[0] = wt[1] = wt[2] = 0;
    for (i = 0; i < num_els; i++) {
       ++wt[ringels[i]];
    }
    if ((wt[0] < min_wt) || (wt[1] < min_wt) || (wt[2] < min_wt)) {
        return FALSE;
    }
    return TRUE;
}


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
 * input array "b", or temp array "t".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

void
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
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t mod_q_mask = q - 1;
    uint16_t i, j, k;

    /* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */

    for (k = 0; k < N; k++)
        t[k] = 0;
    for (j = bi_P1_len; j < bi_P1_len + bi_M1_len; j++) {
        k = bi[j];
        for (i = 0; k < N; ++i, ++k)
            t[k] = t[k] + a[i];
        for (k = 0; i < N; ++i, ++k)
            t[k] = t[k] + a[i];
    }

    /* t[(i+k)%N] = -(sum i=0 through N-1 of a[i] for b[k] = -1) */

    for (k = 0; k < N; k++)
        t[k] = -t[k];

    /* t[(i+k)%N] += sum i=0 through N-1 of a[i] for b[k] = +1 */

    for (j = 0; j < bi_P1_len; j++) {
        k = bi[j];
        for (i = 0; k < N; ++i, ++k)
            t[k] = t[k] + a[i];
        for (k = 0; i < N; ++i, ++k)
            t[k] = t[k] + a[i];
    }

    /* c = (a * b) mod q */

    for (k = 0; k < N; k++)
        c[k] = t[k] & mod_q_mask;
}


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

void
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
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t *t2 = t + N;
    uint16_t  mod_q_mask = q - 1;
    uint16_t  i;


    /* t2 = a * b1 */
    ntru_ring_mult_indices(a, b1i_len, b1i_len, bi, N, q, t, t2);

    /* t2 = (a * b1) * b2 */
    ntru_ring_mult_indices(t2, b2i_len, b2i_len, bi + (b1i_len << 1), N, q,
                           t, t2);

    /* t = a * b3 */
    ntru_ring_mult_indices(a, b3i_len, b3i_len,
                           bi + ((b1i_len + b2i_len) << 1), N, q, t, t);

    /* c = (a * b1 * b2) + (a * b3) */
    for (i = 0; i < N; i++)
        c[i] = (t2[i] + t[i]) & mod_q_mask;
}


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

void
ntru_ring_mult_coefficients(
    uint16_t const *a,          /*  in - pointer to polynomial a */
    uint16_t const *b,          /*  in - pointer to polynomial b */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t const *bptr = b;
    uint16_t        mod_q_mask = q - 1;
    uint16_t        i, k;

    /* c[k] = sum(a[i] * b[k-i]) mod q */
    memset(c, 0, N * sizeof(uint16_t));
    for (k = 0; k < N; k++) {
        i = 0;
        while (i <= k)
            c[k] += a[i++] * *bptr--;
        bptr += N;
        while (i < N)
            c[k] += a[i++] * *bptr--;
        c[k] &= mod_q_mask;
        ++bptr;
    }
}


/* ntru_ring_inv
 *
 * Finds the inverse of a polynomial, a, in (Z/2^rZ)[X]/(X^N - 1).
 *
 * This assumes q is 2^r where 8 < r < 16, so that operations mod q can
 * wait until the end, and only 16-bit arrays need to be used.
 */

bool
ntru_ring_inv(
    uint16_t       *a,          /*  in - pointer to polynomial a */
    uint16_t        N,          /*  in - no. of coefficients in a */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of 2N elements */
    uint16_t       *a_inv)      /* out - address for polynomial a^-1 */
{
    uint8_t  *b = (uint8_t *)t;     /* b cannot be in a_inv since it must be
                                       rotated and copied there as a^-1 mod 2 */
    uint8_t  *c = b + N;            /* c cannot be in a_inv since it exchanges
                                       with b, and b cannot be in a_inv */
    uint8_t  *f = c + N;
    uint8_t  *g = (uint8_t *)a_inv; /* g needs N + 1 bytes */
    uint16_t *t2 = t + N;
    uint16_t  deg_b;
    uint16_t  deg_c;
    uint16_t  deg_f;
    uint16_t  deg_g;
    uint16_t  k = 0;
    bool      done = FALSE;
    uint16_t  i, j;

    /* form a^-1 in (Z/2Z)[X]/X^N - 1) */
    memset(b, 0, (N << 1));                /* clear to init b, c */

    /* b(X) = 1 */
    b[0] = 1;
    deg_b = 0;

    /* c(X) = 0 (cleared above) */
    deg_c = 0;

    /* f(X) = a(X) mod 2 */
    for (i = 0; i < N; i++)
        f[i] = (uint8_t)(a[i] & 1);
    deg_f = N - 1;

    /* g(X) = X^N - 1 */
    g[0] = 1;
    memset(g + 1, 0, N - 1);
    g[N] = 1;
    deg_g = N;

    /* until f(X) = 1 */

	while (!done)
	{

        /* while f[0] = 0, f(X) /= X, c(X) *= X, k++ */

        for (i = 0; (i <= deg_f) && (f[i] == 0); ++i);
        if (i > deg_f)
            return FALSE;
        if (i) {
            f = f + i;
            deg_f = deg_f - i;
            deg_c = deg_c + i;
            for (j = deg_c; j >= i; j--)
                c[j] = c[j-i];
            for (j = 0; j < i; j++)
                c[j] = 0;
            k = k + i;
        }

        /* adjust degree of f(X) if the highest coefficients are zero
         * Note: f[0] = 1 from above so the loop will terminate.
         */

        while (f[deg_f] == 0)
            --deg_f;

        /* if f(X) = 1, done
         * Note: f[0] = 1 from above, so only check the x term and up
         */

        for (i = 1; (i <= deg_f) && (f[i] == 0); ++i);
        if (i > deg_f) {
            done = TRUE;
            break;
        }

        /* if deg_f < deg_g, f <-> g, b <-> c */

        if (deg_f < deg_g) {
            uint8_t *x;

            x = f;
            f = g;
            g = x;
            deg_f ^= deg_g;
            deg_g ^= deg_f;
            deg_f ^= deg_g;
            x = b;
            b = c;
            c = x;
            deg_b ^= deg_c;
            deg_c ^= deg_b;
            deg_b ^= deg_c;
        }

        /* f(X) += g(X), b(X) += c(X) */

        for (i = 0; i <= deg_g; i++)
            f[i] ^= g[i];

        if (deg_c > deg_b)
            deg_b = deg_c;
        for (i = 0; i <= deg_c; i++)
            b[i] ^= c[i];
    }

    /* a^-1 in (Z/2Z)[X]/(X^N - 1) = b(X) shifted left k coefficients */

    j = 0;
    if (k >= N)
        k = k - N;
    for (i = k; i < N; i++)
        a_inv[j++] = (uint16_t)(b[i]);
    for (i = 0; i < k; i++)
        a_inv[j++] = (uint16_t)(b[i]);

    /* lift a^-1 in (Z/2Z)[X]/(X^N - 1) to a^-1 in (Z/qZ)[X]/(X^N -1) */

    for (j = 0; j < 4; ++j) {       /* assumes 256 < q <= 65536 */

        /* a^-1 = a^-1 * (2 - a * a^-1) mod q */

        memcpy(t2, a_inv, N * sizeof(uint16_t));
        ntru_ring_mult_coefficients(a, t2, N, q, t);
        for (i = 0; i < N; ++i)
            t[i] = q - t[i];
        t[0] = t[0] + 2;
        ntru_ring_mult_coefficients(t2, t, N, q, a_inv);
    }

    return TRUE;


}


