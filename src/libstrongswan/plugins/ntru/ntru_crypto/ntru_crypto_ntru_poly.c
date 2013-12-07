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
 
/******************************************************************************
 *
 * File: ntru_crypto_ntru_poly.c
 *
 * Contents: Routines for generating and operating on polynomials in the
 *           NTRU algorithm.
 *
 *****************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "ntru_crypto_ntru_poly.h"

#include "ntru_mgf1.h"

#include <utils/debug.h>

/* ntru_gen_poly
 *
 * Generates polynomials by creating for each polynomial, a list of the
 * indices of the +1 coefficients followed by a list of the indices of
 * the -1 coefficients.
 *
 * If a single polynomial is generated (non-product form), indices_counts
 * contains a single value of the total number of indices (for +1 and -1
 * comefficients combined).
 *
 * If multiple polynomials are generated (for product form), their lists of
 * indices are sequentially stored in the indices buffer.  Each byte of
 * indices_counts contains the total number of indices (for +1 and -1
 * coefficients combined) for a single polynomial, beginning with the
 * low-order byte for the first polynomial.  The high-order byte is unused.
 *
 * Returns NTRU_OK if successful.
 * Returns HASH_BAD_ALG if the algorithm is not supported.
 *
 */

uint32_t
ntru_gen_poly(
    hash_algorithm_t        hash_algid,      /*  in - hash algorithm ID for
                                                      IGF-2 */
    uint8_t                 min_calls,       /*  in - minimum no. of hash
                                                      calls */
    uint16_t                seed_len,        /*  in - no. of octets in seed */
    uint8_t                *seed,            /*  in - pointer to seed */
    uint8_t                *buf,             /*  in - pointer to working
                                                      buffer */
    uint16_t                N,               /*  in - max index + 1 */
    uint8_t                 c_bits,          /*  in - no. bits for candidate */
    uint16_t                limit,           /*  in - conversion to index
                                                      limit */
    bool                    is_product_form, /*  in - if generating multiple
                                                      polys */
    uint32_t                indices_counts,  /*  in - nos. of indices needed */
    uint16_t               *indices)         /* out - address for indices */
{
	uint8_t   md_len;
    uint8_t  *octets;
    uint8_t  *used;
    uint8_t   num_polys;
    uint16_t  num_indices;
    uint16_t  octets_available;
    uint16_t  index_cnt = 0;
    uint8_t   left = 0;
    uint8_t   num_left = 0;
	ntru_mgf1_t *mgf1;

    /* generate minimum MGF1 output */
	DBG2(DBG_LIB, "MGF1 is seeded with %u bytes", seed_len);
	mgf1 = ntru_mgf1_create(hash_algid, chunk_create(seed, seed_len), TRUE);
	if (!mgf1)
	{
		return NTRU_MGF1_FAIL;
	}
	md_len = mgf1->get_hash_size(mgf1);
    octets = buf;
    octets_available = min_calls * md_len;

    /* init indices counts for number of polynomials being generated */
    if (is_product_form) {

        /* number of indices for poly1 is in low byte of indices_counts,
         * number of indices for poly2 and poly3 are in next higher bytes
         */

        num_polys = 3;
        num_indices = (uint16_t)(indices_counts & 0xff);
        indices_counts >>= 8;

    } else {

        /* number of bytes for poly is in low 16 bits of indices_counts */

        num_polys = 1;
        num_indices = (uint16_t)indices_counts;
    }

    /* init used-index array */

    used = buf + octets_available;
    memset(used, 0, N);

    /* generate indices (IGF-2) for all polynomials */
	DBG2(DBG_LIB, "MGF1 generates %u octets for %u indices",
				   octets_available, num_indices);
	if (!mgf1->get_mask(mgf1, octets_available, octets))
	{
		mgf1->destroy(mgf1);
		return NTRU_MGF1_FAIL;
	}

    while (num_polys > 0) {

        /* generate indices for a single polynomial */

        while (index_cnt < num_indices) {
            uint16_t index;
            uint8_t  num_needed;

            /* form next index to convert to an index */

            do {
                /* use any leftover bits first */

                if (num_left != 0) {
                    index = left << (c_bits - num_left);
                } else {
                    index = 0;
                }

                /* get the rest of the bits needed from new octets */

                num_needed = c_bits - num_left;
                while (num_needed != 0)
				{

                    /* get another octet */
                    if (octets_available == 0)
					{
                        octets = buf;
                        octets_available = md_len;

						DBG2(DBG_LIB, "MGF1 generates another %u octets for the "
									  "remaining %u indices", octets_available,
									   num_indices - index_cnt);
						if (!mgf1->get_mask(mgf1, octets_available, octets))
						{
							mgf1->destroy(mgf1);
							return NTRU_MGF1_FAIL;
						}
                    }
                    left = *octets++;
                    --octets_available;

					if (num_needed <= 8)
					{

                        /* all bits needed to fill the index are in this octet */

                        index |= ((uint16_t)(left)) >> (8 - num_needed);
                        num_left = 8 - num_needed;
                        num_needed = 0;
                        left &= 0xff >> (8 - num_left);

                    } else {

                        /* another octet will be needed after using this
                         * whole octet
                         */

                        index |= ((uint16_t)left) << (num_needed - 8);
                        num_needed -= 8;
                    }
                }
            } while (index >= limit);

            /* form index and check if unique */

            index %= N;
			if (!used[index])
			{
                used[index] = 1;
                indices[index_cnt] = index;
                ++index_cnt;
            }
        }
        --num_polys;

        /* init for next polynomial if another polynomial to be generated */

		if (num_polys > 0)
		{
            memset(used, 0, N);
            num_indices = num_indices +
                          (uint16_t)(indices_counts & 0xff);
            indices_counts >>= 8;
        }
    }
	mgf1->destroy(mgf1);

	return NTRU_OK;
}


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


