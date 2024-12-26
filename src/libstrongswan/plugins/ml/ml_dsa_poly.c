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

#include "ml_dsa_poly.h"
#include "ml_utils.h"

/**
 * Precalculated Zeta^BitRev_8(i) mod q values for NTT Algorithms 41 and 42
 * The values are in (centered) Montgomery form, not the verbatim values of
 * Appendix B in FIPS 204.
 */
static const int32_t ml_dsa_zetas[ML_DSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*
 * Described in header
 */
void ml_dsa_poly_ntt(ml_dsa_poly_t *a)
{
	u_int len, start, j, k = 0;
	int32_t zeta, t;

	for (len = ML_DSA_N/2; len > 0; len >>= 1)
	{
		for (start = 0; start < ML_DSA_N; start = j + len)
		{
			zeta = ml_dsa_zetas[++k];
			for(j = start; j < start + len; ++j)
			{
				t = ml_montgomery_reduce((int64_t)zeta * a->f[j + len]);
				a->f[j + len] = a->f[j] - t;
				a->f[j] = a->f[j] + t;
			}
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_inv_ntt(ml_dsa_poly_t *a)
{
	u_int start, len, j, k = ML_DSA_N;
	int32_t t, zeta;

	/* scaling factor 256^-1 mod q with squared Montgomery multiplier to
	 * implicitly convert results to Montgomery form (i.e. 2^64/256 mod q)
	 */
	const int32_t factor = 41978;

	for (len = 1; len < ML_DSA_N; len <<= 1)
	{
		for (start = 0; start < ML_DSA_N; start = j + len)
		{
			zeta = -ml_dsa_zetas[--k];
			for (j = start; j < start + len; ++j)
			{
				t = a->f[j];
				a->f[j] = t + a->f[j + len];
				a->f[j + len] = t - a->f[j + len];
				a->f[j + len] = ml_montgomery_reduce((int64_t)zeta * a->f[j + len]);
			}
		}
	}

	for(j = 0; j < ML_DSA_N; ++j)
	{
		a->f[j] = ml_montgomery_reduce((int64_t)factor * a->f[j]);
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_ntt_vec(u_int k, ml_dsa_poly_t *a)
{
	while (k--)
	{
		ml_dsa_poly_ntt(&a[k]);
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_inv_ntt_vec(u_int k, ml_dsa_poly_t *a)
{
	while (k--)
	{
		ml_dsa_poly_inv_ntt(&a[k]);
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_copy_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b)
{
	while (k--)
	{
		b[k] = a[k];
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_add_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						 ml_dsa_poly_t *res)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			res[k].f[n] = a[k].f[n] + b[k].f[n];
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_sub_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						 ml_dsa_poly_t *res)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			res[k].f[n] = a[k].f[n] - b[k].f[n];
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_mult_const_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
								ml_dsa_poly_t *res)
{
	u_int n;

	/* pointwise product of polynomial vector b with a polynomial a */
	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			res[k].f[n] = ml_montgomery_reduce((int64_t)a->f[n] * b[k].f[n]);
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_mult_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						  ml_dsa_poly_t *res)
{
	u_int n;

	/* initialize result polynomial to all zeros */
	for (n = 0; n < ML_DSA_N; n++)
	{
		res->f[n] = 0;
	}

	/* compute the inner product of vectors a and b */
	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			res->f[n] += ml_montgomery_reduce((int64_t)a[k].f[n] * b[k].f[n]);
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_mult_mat(u_int k, u_int l, ml_dsa_poly_t *a, ml_dsa_poly_t *b,
						  ml_dsa_poly_t *res)
{
	u_int i;

	for (i = 0; i < k; i++)
	{
		ml_dsa_poly_mult_vec(l, &a[i*l], b, &res[i]);
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_reduce_vec(u_int k, ml_dsa_poly_t *a)
{
	int32_t r;
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			r = (a[k].f[n] + (1 << 22)) >> 23;
			a[k].f[n] -= r * ML_DSA_Q;
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_cond_add_q_vec(u_int k, ml_dsa_poly_t *a)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			a[k].f[n] += (a[k].f[n] >> 31) & ML_DSA_Q;
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_power2round_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *a0,
								 ml_dsa_poly_t *a1)
{
	int32_t t0, t1;
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			t1 = (a[k].f[n] + (1 << (ML_DSA_D-1)) - 1) >> ML_DSA_D;
			t0 =  a[k].f[n] - (t1 << ML_DSA_D);

			a0[k].f[n] = t0;
			a1[k].f[n] = t1;
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_shift_left_vec(u_int k, ml_dsa_poly_t *a)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			a[k].f[n] <<= ML_DSA_D;
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_decompose_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *a0,
							   ml_dsa_poly_t *a1, int32_t gamma2)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			ml_decompose(a[k].f[n], &a0[k].f[n], &a1[k].f[n], gamma2);
		}
	}
}

/*
 * Described in header
 */
void ml_dsa_poly_use_hint_vec(u_int k, ml_dsa_poly_t *a, ml_dsa_poly_t *h,
							  ml_dsa_poly_t *a1, int32_t gamma2)
{
	u_int n;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
			a1[k].f[n] = ml_use_hint(a[k].f[n], h[k].f[n], gamma2);
		}
	}
}

/*
 * Described in header
 */
u_int ml_dsa_poly_make_hint_vec(u_int k, ml_dsa_poly_t *a0, ml_dsa_poly_t *a1,
								ml_dsa_poly_t *h, int32_t gamma2)
{
	u_int n, s = 0;

	while (k--)
	{
		for (n = 0; n < ML_DSA_N; n++)
		{
	  		h[k].f[n] = ml_make_hint(a0[k].f[n], a1[k].f[n], gamma2);
	  		s += h[k].f[n];
		}
	}

	return s;
}

/*
 * Described in header
 */
bool ml_dsa_poly_check_bound(ml_dsa_poly_t *a, int32_t bound)
{
	int32_t t;
	u_int n;

  /* it is ok to leak which coefficient violates the bound since the probability
   * for each coefficient is independent of secret data but we must not leak the
   * sign of the centralized representative.
   */
	for (n = 0; n < ML_DSA_N; n++)
	{
		t = a->f[n] >> 31;
		t = a->f[n] - (t & 2*a->f[n]);

		if (t >= bound)
		{
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Described in header
 */
bool ml_dsa_poly_check_bound_vec(u_int k, ml_dsa_poly_t *a, int32_t bound)
{
	while (k--)
	{
		if (!ml_dsa_poly_check_bound(&a[k], bound))
		{
			return FALSE;
		}
	}

	return TRUE;
}
