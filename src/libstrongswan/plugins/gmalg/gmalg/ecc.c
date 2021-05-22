#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/swab.h>

#include "debug.h"
#include "ecc.h"

extern struct ecc_curve ecc_curve;

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
#define SUPPORTS_INT128 1
#else
#define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
	uint64_t m_low;
	uint64_t m_high;
} uint128_t;
#endif

void vli_clear(u8 *vli)
{
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		vli[i] = 0;
	}
}

/* Returns true if vli == 0, false otherwise. */
int vli_is_zero(u8 *vli)
{
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		if (vli[i])
			return 0;
	}

	return 1;
}

/* Returns nonzero if bit bit of vli is set. */
u8 vli_test_bit(u8 *vli, uint bit)
{
	return (vli[bit/8] & ((u8)1 << (bit % 8)));
}

/* Counts the number of 8-bit "digits" in vli. */
u32 vli_num_digits(u8 *vli)
{
	int i;
	/* Search from the end until we find a non-zero digit.
	 * We do it in reverse because we expect that most digits will
	 * be nonzero.
	 */
	for (i = ECC_NUMWORD - 1; i >= 0 && vli[i] == 0; --i);

	return (i + 1);
}

/* Counts the number of bits required for vli. */
u32 vli_num_bits(u8 *vli)
{
	u32 i, num_digits;
	u8 digit;

	num_digits = vli_num_digits(vli);
	if (num_digits == 0)
		return 0;

	digit = vli[num_digits - 1];
	for (i = 0; digit; ++i)
		digit >>= 1;

	return ((num_digits - 1) * 8 + i);
}

/* Sets dest = src. */
void vli_set(u8 *dest, u8 *src)
{
	u32 i;

	for (i = 0; i < ECC_NUMWORD; ++i)
		dest[i] = src[i];
}

/* Returns sign of left - right. */
int vli_cmp(u8 *left, u8 *right)
{
	int i;

	for (i = ECC_NUMWORD - 1; i >= 0; --i) {
		if (left[i] > right[i])
			return 1;
		else if (left[i] < right[i])
			return -1;
	}
	return 0;
}

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 8.
 */
u8 vli_lshift(u8 *result, u8 *in, u32 shift)
{
	u8 carry = 0;
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		u8 temp = in[i];
		result[i] = (temp << shift) | carry;
		carry = temp >> (8 - shift);
	}

	return carry;
}

/* Computes vli = vli >> 1. */
void vli_rshift1(u8 *vli)
{
	u8 *end = vli;
	u8 carry = 0;

	vli += ECC_NUMWORD;
	while (vli-- > end)
	{
		u8 temp = *vli;
		*vli = (temp >> 1) | carry;
		carry = temp << 7;
	}
}

/* Computes result = left + right, returning carry. Can modify in place. */
u8 vli_add(u8 *result, u8 *left, u8 *right)
{
	u8 carry = 0;
	u32 i;

	for(i=0; i<ECC_NUMWORD; ++i){
		u8 sum;

		sum = left[i] + right[i] + carry;
		if (sum != left[i]) {
			carry = (sum < left[i]);
		}
		result[i] = sum;
	}

	return carry;
}

/* Computes result = left - right, returning borrow. Can modify in place. */
u8 vli_sub(u8 *result, u8 *left, u8 *right)
{
	u8 borrow = 0;
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		u8 diff;

		diff = left[i] - right[i] - borrow;
		if (diff != left[i])
			borrow = (diff > left[i]);

		result[i] = diff;
	}

	return borrow;
}

/* Computes result = left * right. */
void vli_mult(u8 *result, u8 *left, u8 *right)
{
	u16 r01 = 0;
	u8 r2 = 0;
	int i, k;

	/* Compute each digit of result in sequence, maintaining the carries. */
	for (k = 0; k < ECC_NUMWORD*2 - 1; ++k) {
		int min = (k < ECC_NUMWORD ? 0 : (k + 1) - ECC_NUMWORD);
		for (i = min; i <= k && i < ECC_NUMWORD; ++i) {
			u16 product = (u16)left[i] * right[k-i];
			r01 = r01 + product;
			r2 += (r01 < product);
		}
		result[k] = (u8)r01;
		r01 = (r01 >> 8) | (((u16)r2) << 8);
		r2 = 0;
	}

	result[ECC_NUMWORD*2 - 1] = (u8)r01;
}

/* Computes result = left^2. */
void vli_square(u8 *result, u8 *left)
{
	u16 r01 = 0;
	u8 r2 = 0;
	int i, k;

	for (k = 0; k < ECC_NUMWORD*2 - 1; ++k) {
		uint min = (k < ECC_NUMWORD ? 0 : (k + 1) - ECC_NUMWORD);
		for (i = min; i <= k && i <= k - i; ++i) {
			u16 product = (u16)left[i] * left[k-i];
			if (i < k - i) {
				r2 += product >> 15;
				product *= 2;
			}
			r01 += product;
			r2 += (r01 < product);
		}
		result[k] = (u8)r01;
		r01 = (r01 >> 8) | (((u16)r2) << 8);
		r2 = 0;
	}

	result[ECC_NUMWORD*2 - 1] = (u8)r01;
}

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_add(u8 *result, u8 *left, u8 *right, u8 *mod)
{
	u8 carry;

	carry = vli_add(result, left, right);
	/* result > mod (result = mod + remainder), so subtract mod to
	 * get remainder.
	 */

	if(carry || vli_cmp(result, mod) >= 0) {
		/* result > mod (result = mod + remainder), so subtract mod to get remainder. */
		vli_sub(result, result, mod);
	}
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_sub(u8 *result, u8 *left, u8 *right, u8 *mod)
{
	u8 borrow;

	borrow = vli_sub(result, left, right);
	/* In this case, result == -diff == (max int) - diff.
	 * Since -x % d == d - x, we can get the correct result from
	 * result + mod (with overflow).
	 */
	if(borrow)
		vli_add(result, result, mod);
}

void vli_mmod_fast(u8 *result, u8 *product, u8* mod)
{
	u8 tmp1[ECC_NUMWORD];
	u8 tmp2[ECC_NUMWORD];
	u8 tmp3[ECC_NUMWORD];
	int carry = 0;

	vli_set(result, product);
	vli_clear(tmp1);
	vli_clear(tmp2);
	vli_clear(tmp3);

	/* Y0 */
	tmp1[0] = tmp1[12] = tmp1[28] = product[32];
	tmp1[1] = tmp1[13] = tmp1[29] = product[33];
	tmp1[2] = tmp1[14] = tmp1[30] = product[34];
	tmp1[3] = tmp1[15] = tmp1[31] = product[35];
	tmp2[8] = product[32];
	tmp2[9] = product[33];
	tmp2[10] = product[34];
	tmp2[11] = product[35];
	carry += vli_add(result, result, tmp1);
	carry -= vli_sub(result, result, tmp2);

	/* Y1 */
	tmp1[0] = tmp1[4] = tmp1[16] = tmp1[28] = product[36];
	tmp1[1] = tmp1[5] = tmp1[17] = tmp1[29] = product[37];
	tmp1[2] = tmp1[6] = tmp1[18] = tmp1[30] = product[38];
	tmp1[3] = tmp1[7] = tmp1[19] = tmp1[31] = product[39];
	tmp1[12] = tmp1[13] = tmp1[14] = tmp1[15] = 0;
	tmp2[8] = product[36];
	tmp2[9] = product[37];
	tmp2[10] = product[38];
	tmp2[11] = product[39];
	carry += vli_add(result, result, tmp1);
	carry -= vli_sub(result, result, tmp2);

	/* Y2 */
	tmp1[0] = tmp1[4] = tmp1[20] = tmp1[28] = product[40];
	tmp1[1] = tmp1[5] = tmp1[21] = tmp1[29] = product[41];
	tmp1[2] = tmp1[6] = tmp1[22] = tmp1[30] = product[42];
	tmp1[3] = tmp1[7] = tmp1[23] = tmp1[31] = product[43];
	tmp1[16] = tmp1[17] = tmp1[18] = tmp1[19] = 0;
	carry += vli_add(result, result, tmp1);

	/* Y3 */
	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[24] = tmp1[28] = product[44];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[25] = tmp1[29] = product[45];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[26] = tmp1[30] = product[46];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[27] = tmp1[31] = product[47];
	tmp1[20] = tmp1[21] = tmp1[22] = tmp1[23] = 0;
	carry += vli_add(result, result, tmp1);

	/* Y4 */
	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[28] = tmp3[28] = product[48];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[29] = tmp3[29] = product[49];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[30] = tmp3[30] = product[50];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[31] = tmp3[31] = product[51];
	tmp1[24] = tmp1[25] = tmp1[26] = tmp1[27] = 0;
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);

	/* Y5 */
	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[28] = product[52];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[29] = product[53];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[30] = product[54];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[31] = product[55];
	tmp2[8] = product[52];
	tmp2[9] = product[53];
	tmp2[10] = product[54];
	tmp2[11] = product[55];
	tmp3[0] = tmp3[12] = tmp3[28] = product[52];
	tmp3[1] = tmp3[13] = tmp3[29] = product[53];
	tmp3[2] = tmp3[14] = tmp3[30] = product[54];
	tmp3[3] = tmp3[15] = tmp3[31] = product[55];
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry -= vli_sub(result, result, tmp2);

	/* Y6 */
	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[24] = tmp1[28] = product[56];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[25] = tmp1[29] = product[57];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[26] = tmp1[30] = product[58];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[27] = tmp1[31] = product[59];
	tmp2[8] = product[56];
	tmp2[9] = product[57];
	tmp2[10] = product[58];
	tmp2[11] = product[59];
	tmp3[0] = tmp3[4] = tmp3[16] = tmp3[28] = product[56];
	tmp3[1] = tmp3[5] = tmp3[17] = tmp3[29] = product[57];
	tmp3[2] = tmp3[6] = tmp3[18] = tmp3[30] = product[58];
	tmp3[3] = tmp3[7] = tmp3[19] = tmp3[31] = product[59];
	tmp3[12] = tmp3[13] = tmp3[14] = tmp3[15] = 0;
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry -= vli_sub(result, result, tmp2);

	/* Y7 */
	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[24] = tmp1[28] = product[60];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[25] = tmp1[29] = product[61];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[26] = tmp1[30] = product[62];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[27] = tmp1[31] = product[63];
	tmp3[0] = tmp3[4] = tmp3[20]  = product[60];
	tmp3[1] = tmp3[5] = tmp3[21]  = product[61];
	tmp3[2] = tmp3[6] = tmp3[22]  = product[62];
	tmp3[3] = tmp3[7] = tmp3[23]  = product[63];
	tmp3[16] = tmp3[17] = tmp3[18] = tmp3[19] = tmp3[28] = tmp3[29] = tmp3[30] = tmp3[31] = 0;
	tmp2[28] = product[60];
	tmp2[29] = product[61];
	tmp2[30] = product[62];
	tmp2[31] = product[63];
	tmp2[8] = tmp2[9] = tmp2[10] = tmp2[11] = 0;
	carry += vli_lshift(tmp2, tmp2, 1);
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry += vli_add(result, result, tmp2);

	if (carry < 0) {
		do {
			carry += vli_add(result, result, mod);
		} while(carry < 0);
	} else {
		while (carry || vli_cmp(mod, result) != 1)
		{
			carry -= vli_sub(result, result, mod);
		}
	}
}

/* Computes result = (left * right) % ecc_curve.p. */
void vli_mod_mult_fast(u8 *result, u8 *left, u8 *right, u8 *mod)
{
	u8 product[2 * ECC_NUMWORD];

	vli_mult(product, left, right);
	vli_mmod_fast(result, product, mod);
}

/* Computes result = left^2 % ecc_curve.p. */
void vli_mod_square_fast(u8 *result, u8 *left, u8 *mod)
{
	u8 product[2 * ECC_NUMWORD];

	vli_square(product, left);
	vli_mmod_fast(result, product, mod);
}

/* Computes result = (left * right) % mod. */
void vli_mod_mult(u8 *result, u8 *left, u8 *right, u8 *mod)
{
	u8 product[2 * ECC_NUMWORD];
	u8 modMultiple[2 * ECC_NUMWORD];
	uint digitShift, bitShift;
	uint productBits;
	uint modBits = vli_num_bits(mod);

	vli_mult(product, left, right);
	productBits = vli_num_bits(product + ECC_NUMWORD);
	if (productBits) {
		productBits += ECC_NUMWORD * 8;
	} else {
		productBits = vli_num_bits(product);
	}

	if (productBits < modBits) {
		/* product < mod. */
		vli_set(result, product);
		return;
	}

	/* Shift mod by (leftBits - modBits). This multiplies mod by the largest
	   power of two possible while still resulting in a number less than left. */
	vli_clear(modMultiple);
	vli_clear(modMultiple + ECC_NUMWORD);
	digitShift = (productBits - modBits) / 8;
	bitShift = (productBits - modBits) % 8;
	if (bitShift) {
		modMultiple[digitShift + ECC_NUMWORD] = vli_lshift(modMultiple + digitShift, mod, bitShift);
	} else {
		vli_set(modMultiple + digitShift, mod);
	}

	/* Subtract all multiples of mod to get the remainder. */
	vli_clear(result);
	result[0] = 1; /* Use result as a temp var to store 1 (for subtraction) */
	while (productBits > ECC_NUMWORD * 8 || vli_cmp(modMultiple, mod) >= 0)
	{
		int cmp = vli_cmp(modMultiple + ECC_NUMWORD, product + ECC_NUMWORD);
		if (cmp < 0 || (cmp == 0 && vli_cmp(modMultiple, product) <= 0)) {
			if (vli_sub(product, product, modMultiple))
			{
				/* borrow */
				vli_sub(product + ECC_NUMWORD, product + ECC_NUMWORD, result);
			}
			vli_sub(product + ECC_NUMWORD, product + ECC_NUMWORD, modMultiple + ECC_NUMWORD);
		}
		u8 carry = (modMultiple[ECC_NUMWORD] & 0x01) << 7;
		vli_rshift1(modMultiple + ECC_NUMWORD);
		vli_rshift1(modMultiple);
		modMultiple[ECC_NUMWORD-1] |= carry;

		--productBits;
	}
	vli_set(result, product);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(u8 *result, u8 *input, u8 *mod)
{
	u8 a[ECC_NUMWORD], b[ECC_NUMWORD], u[ECC_NUMWORD], v[ECC_NUMWORD];
	u8 carry;
	int cmpResult;

	if (vli_is_zero(input)) {
		vli_clear(result);
		return;
	}

	vli_set(a, input);
	vli_set(b, mod);
	vli_clear(u);
	u[0] = 1;
	vli_clear(v);

	while ((cmpResult = vli_cmp(a, b)) != 0) {
		carry = 0;
		if (EVEN(a)) {
			vli_rshift1(a);
			if (!EVEN(u)) {
				carry = vli_add(u, u, mod);
			}
			vli_rshift1(u);
			if (carry) {
				u[ECC_NUMWORD-1] |= 0x80;
			}
		} else if (EVEN(b)) {
			vli_rshift1(b);
			if (!EVEN(v)) {
				carry = vli_add(v, v, mod);
			}
			vli_rshift1(v);
			if (carry) {
				v[ECC_NUMWORD-1] |= 0x80;
			}
		} else if (cmpResult > 0) {
			vli_sub(a, a, b);
			vli_rshift1(a);
			if (vli_cmp(u, v) < 0) {
				vli_add(u, u, mod);
			}
			vli_sub(u, u, v);
			if (!EVEN(u)) {
				carry = vli_add(u, u, mod);
			}
			vli_rshift1(u);
			if (carry) {
				u[ECC_NUMWORD-1] |= 0x80;
			}
		} else {
			vli_sub(b, b, a);
			vli_rshift1(b);
			if (vli_cmp(v, u) < 0) {
				vli_add(v, v, mod);
			}
			vli_sub(v, v, u);
			if (!EVEN(v)) {
				carry = vli_add(v, v, mod);
			}
			vli_rshift1(v);
			if (carry) {
				v[ECC_NUMWORD-1] |= 0x80;
			}
		}
	}

	vli_set(result, u);
}

/* Returns 1 if point is the point at infinity, 0 otherwise. */
int ecc_point_is_zero(ecc_point *point)
{
	return (vli_is_zero(point->x) && vli_is_zero(point->y));
}

/* Double in place */
void ecc_point_double_jacobian(u8 *X1, u8 *Y1, u8 *Z1)
{
	/* t1 = X, t2 = Y, t3 = Z */
	u8 t4[ECC_NUMWORD];
	u8 t5[ECC_NUMWORD];

	if(vli_is_zero(Z1))
		return;

	vli_mod_square_fast(t4, Y1, ecc_curve.p);   /* t4 = y1^2 */
	vli_mod_mult_fast(t5, X1, t4, ecc_curve.p); /* t5 = x1*y1^2 = A */
	vli_mod_square_fast(t4, t4, ecc_curve.p);   /* t4 = y1^4 */
	vli_mod_mult_fast(Y1, Y1, Z1, ecc_curve.p); /* t2 = y1*z1 = z3 */
	vli_mod_square_fast(Z1, Z1, ecc_curve.p);   /* t3 = z1^2 */

	vli_mod_add(X1, X1, Z1, ecc_curve.p); /* t1 = x1 + z1^2 */
	vli_mod_add(Z1, Z1, Z1, ecc_curve.p); /* t3 = 2*z1^2 */
	vli_mod_sub(Z1, X1, Z1, ecc_curve.p); /* t3 = x1 - z1^2 */
	vli_mod_mult_fast(X1, X1, Z1, ecc_curve.p);    /* t1 = x1^2 - z1^4 */

	vli_mod_add(Z1, X1, X1, ecc_curve.p); /* t3 = 2*(x1^2 - z1^4) */
	vli_mod_add(X1, X1, Z1, ecc_curve.p); /* t1 = 3*(x1^2 - z1^4) */
	if (vli_test_bit(X1, 0)) {
		u8 carry = vli_add(X1, X1, ecc_curve.p);
		vli_rshift1(X1);
		X1[ECC_NUMWORD-1] |= carry << 7;
	} else {
		vli_rshift1(X1);
	}

	/* t1 = 3/2*(x1^2 - z1^4) = B */
	vli_mod_square_fast(Z1, X1, ecc_curve.p);      /* t3 = B^2 */
	vli_mod_sub(Z1, Z1, t5, ecc_curve.p); /* t3 = B^2 - A */
	vli_mod_sub(Z1, Z1, t5, ecc_curve.p); /* t3 = B^2 - 2A = x3 */
	vli_mod_sub(t5, t5, Z1, ecc_curve.p); /* t5 = A - x3 */
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);    /* t1 = B * (A - x3) */
	vli_mod_sub(t4, X1, t4, ecc_curve.p); /* t4 = B * (A - x3) - y1^4 = y3 */

	vli_set(X1, Z1);
	vli_set(Z1, Y1);
	vli_set(Y1, t4);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(u8 *X1, u8 *Y1, u8 *Z)
{
	u8 t1[ECC_NUMWORD];

	vli_mod_square_fast(t1, Z, ecc_curve.p);    /* z^2 */
	vli_mod_mult_fast(X1, X1, t1, ecc_curve.p); /* x1 * z^2 */
	vli_mod_mult_fast(t1, t1, Z, ecc_curve.p);  /* z^3 */
	vli_mod_mult_fast(Y1, Y1, t1, ecc_curve.p); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(u8 *X1, u8 *Y1, u8 *X2, u8 *Y2, u8 *initialZ)
{
	u8 z[ECC_NUMWORD];

	vli_set(X2, X1);
	vli_set(Y2, Y1);

	if(initialZ)
	{
		vli_set(z, initialZ);
	}else{
		vli_clear(z);
		z[0] = 1;
	}
	apply_z(X1, Y1, z);

	ecc_point_double_jacobian(X1, Y1, z);

	apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
   */
void XYcZ_add(u8 *X1, u8 *Y1, u8 *X2, u8 *Y2)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u8 t5[ECC_NUMWORD];

	vli_mod_sub(t5, X2, X1, ecc_curve.p); /* t5 = x2 - x1 */
	vli_mod_square_fast(t5, t5, ecc_curve.p);      /* t5 = (x2 - x1)^2 = A */
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);    /* t1 = x1*A = B */
	vli_mod_mult_fast(X2, X2, t5, ecc_curve.p);    /* t3 = x2*A = C */
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); /* t4 = y2 - y1 */
	vli_mod_square_fast(t5, Y2, ecc_curve.p);      /* t5 = (y2 - y1)^2 = D */

	vli_mod_sub(t5, t5, X1, ecc_curve.p); /* t5 = D - B */
	vli_mod_sub(t5, t5, X2, ecc_curve.p); /* t5 = D - B - C = x3 */
	vli_mod_sub(X2, X2, X1, ecc_curve.p); /* t3 = C - B */
	vli_mod_mult_fast(Y1, Y1, X2, ecc_curve.p);    /* t2 = y1*(C - B) */
	vli_mod_sub(X2, X1, t5, ecc_curve.p); /* t3 = B - x3 */
	vli_mod_mult_fast(Y2, Y2, X2, ecc_curve.p);    /* t4 = (y2 - y1)*(B - x3) */
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); /* t4 = y3 */

	vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 * or P => P - Q, Q => P + Q
 */
void XYcZ_addC(u8 *X1, u8 *Y1, u8 *X2, u8 *Y2)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u8 t5[ECC_NUMWORD];
	u8 t6[ECC_NUMWORD];
	u8 t7[ECC_NUMWORD];

	vli_mod_sub(t5, X2, X1, ecc_curve.p); /* t5 = x2 - x1 */
	vli_mod_square_fast(t5, t5, ecc_curve.p);      /* t5 = (x2 - x1)^2 = A */
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);    /* t1 = x1*A = B */
	vli_mod_mult_fast(X2, X2, t5, ecc_curve.p);    /* t3 = x2*A = C */
	vli_mod_add(t5, Y2, Y1, ecc_curve.p); /* t4 = y2 + y1 */
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); /* t4 = y2 - y1 */

	vli_mod_sub(t6, X2, X1, ecc_curve.p); /* t6 = C - B */
	vli_mod_mult_fast(Y1, Y1, t6, ecc_curve.p);    /* t2 = y1 * (C - B) */
	vli_mod_add(t6, X1, X2, ecc_curve.p); /* t6 = B + C */
	vli_mod_square_fast(X2, Y2, ecc_curve.p);      /* t3 = (y2 - y1)^2 */
	vli_mod_sub(X2, X2, t6, ecc_curve.p); /* t3 = x3 */

	vli_mod_sub(t7, X1, X2, ecc_curve.p); /* t7 = B - x3 */
	vli_mod_mult_fast(Y2, Y2, t7, ecc_curve.p);    /* t4 = (y2 - y1)*(B - x3) */
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); /* t4 = y3 */

	vli_mod_square_fast(t7, t5, ecc_curve.p);      /* t7 = (y2 + y1)^2 = F */
	vli_mod_sub(t7, t7, t6, ecc_curve.p); /* t7 = x3' */
	vli_mod_sub(t6, t7, X1, ecc_curve.p); /* t6 = x3' - B */
	vli_mod_mult_fast(t6, t6, t5, ecc_curve.p);    /* t6 = (y2 + y1)*(x3' - B) */
	vli_mod_sub(Y1, t6, Y1, ecc_curve.p); /* t2 = y3' */

	vli_set(X1, t7);
}

void ecc_point_mult(ecc_point *result, ecc_point *point, u8 *scalar, u8 *initialZ)
{
	/* R0 and R1 */
	u8 Rx[2][ECC_NUMWORD];
	u8 Ry[2][ECC_NUMWORD];
	u8 z[ECC_NUMWORD];
	int i, nb;

	vli_set(Rx[1], point->x);
	vli_set(Ry[1], point->y);

	XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initialZ);

	for (i = vli_num_bits(scalar) - 2; i > 0; --i) {
		nb = !vli_test_bit(scalar, i);
		XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
		XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
	}

	nb = !vli_test_bit(scalar, 0);
	XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

	/* Find final 1/Z value. */
	vli_mod_sub(z, Rx[1], Rx[0], ecc_curve.p); /* X1 - X0 */
	vli_mod_mult_fast(z, z, Ry[1-nb], ecc_curve.p);     /* Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, point->x, ecc_curve.p);   /* xP * Yb * (X1 - X0) */
	vli_mod_inv(z, z, ecc_curve.p);            /* 1 / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, point->y, ecc_curve.p);   /* yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, Rx[1-nb], ecc_curve.p);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
	/* End 1/Z calculation */

	XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);

	apply_z(Rx[0], Ry[0], z);

	vli_set(result->x, Rx[0]);
	vli_set(result->y, Ry[0]);
}

static u32 max(u32 a, u32 b)
{
        return (a > b ? a : b);
}

void ecc_point_mult2(ecc_point *result, ecc_point *g, ecc_point *p, u8 *s, u8 *t)
{
	u8 tx[ECC_NUMWORD];
	u8 ty[ECC_NUMWORD];
	u8 tz[ECC_NUMWORD];
	u8 z[ECC_NUMWORD];
	ecc_point sum;
	u8 *rx;
	u8 *ry;
	int i;

	rx = result->x;
	ry = result->y;

	/* Calculate sum = G + Q. */
	vli_set(sum.x, p->x);
	vli_set(sum.y, p->y);
	vli_set(tx, g->x);
	vli_set(ty, g->y);

	vli_mod_sub(z, sum.x, tx, ecc_curve.p); /* Z = x2 - x1 */
	XYcZ_add(tx, ty, sum.x, sum.y);
	vli_mod_inv(z, z, ecc_curve.p); /* Z = 1/Z */
	apply_z(sum.x, sum.y, z);

	/* Use Shamir's trick to calculate u1*G + u2*Q */
	ecc_point *points[4] = {NULL, g, p, &sum};
	u32 numBits = max(vli_num_bits(s), vli_num_bits(t));

	ecc_point *point = points[(!!vli_test_bit(s, numBits-1)) | ((!!vli_test_bit(t, numBits-1)) << 1)];
	vli_set(rx, point->x);
	vli_set(ry, point->y);
	vli_clear(z);
	z[0] = 1;

	for (i = numBits - 2; i >= 0; --i) {
		ecc_point_double_jacobian(rx, ry, z);

		int index = (!!vli_test_bit(s, i)) | ((!!vli_test_bit(t, i)) << 1);
		ecc_point *point = points[index];
		if(point) {
			vli_set(tx, point->x);
			vli_set(ty, point->y);
			apply_z(tx, ty, z);
			vli_mod_sub(tz, rx, tx, ecc_curve.p); /* Z = x2 - x1 */
			XYcZ_add(tx, ty, rx, ry);
			vli_mod_mult_fast(z, z, tz, ecc_curve.p);
		}
	}

	vli_mod_inv(z, z, ecc_curve.p); /* Z = 1/Z */
	apply_z(rx, ry, z);
}

void ecc_point_add(ecc_point *result, ecc_point *left, ecc_point *right)
{
	u8 x1[ECC_NUMWORD];
	u8 y1[ECC_NUMWORD];
	u8 x2[ECC_NUMWORD];
	u8 y2[ECC_NUMWORD];
	u8 z[ECC_NUMWORD];

	vli_set(x1, left->x);
	vli_set(y1, left->y);
	vli_set(x2, right->x);
	vli_set(y2, right->y);

	vli_mod_sub(z, x2, x1, ecc_curve.p); /* Z = x2 - x1 */

	XYcZ_add(x1, y1, x2, y2);
	vli_mod_inv(z, z, ecc_curve.p); /* Z = 1/Z */
	apply_z(x2,y2, z);

	vli_set(result->x, x2);
	vli_set(result->y, y2);
}
