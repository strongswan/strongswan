/*
 * Copyright (C) 2024 Tobias Brunner
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

#include "ml_utils.h"

/*
 * Described in header
 */
void ml_assign_cond_int16(int16_t *dst, int16_t val, uint16_t cond)
{
	cond = -cond;
	*dst ^= cond & (val ^ *dst);
}

/*
 * Described in header
 */
uint32_t ml_read_bytes_le(uint8_t *buf, size_t len)
{
	uint32_t x = 0;
	int i;

	for (i = 0; i < len; i++)
	{
		x |= (uint32_t)buf[i] << (8 * i);
	}
	return x;
}

/*
 * Described in header
 */
void ml_write_bytes_le(uint8_t *buf, size_t len, uint32_t val)
{
	int i;

	for (i = 0; i < len; i++)
	{
		buf[i] = val;
		val >>= 8;
	}
}

/*
 * Described in header
 */
void ml_decompose(int32_t a, int32_t *a0, int32_t *a1, int32_t gamma2)
{
	int32_t t0, t1;

	t1  = (a + 127) >> 7;

	if (gamma2 == (ML_DSA_Q-1)/32)
	{
		t1  = (t1 * 1025 + (1 << 21)) >> 22;
		t1 &= 15;
	}
	else
	{
		t1  = (t1 * 11275 + (1 << 23)) >> 24;
		t1 ^= ((43 - t1) >> 31) & t1;
	}

	t0 = a - t1 * 2 * gamma2;
	t0 -= (((ML_DSA_Q-1)/2 - t0) >> 31) & ML_DSA_Q;

	*a0 = t0;
	*a1 = t1;
}

/*
 * Described in header
 */
int32_t ml_use_hint(int32_t a, int32_t hint, int32_t gamma2)
{
	int32_t a0, a1;

	ml_decompose(a, &a0, &a1, gamma2);

	if (hint == 0)
	{
		return a1;
	}
	if (gamma2 == (ML_DSA_Q-1)/32)
	{
		if (a0 > 0)
		{
			return (a1 + 1) & 15;
		}
		else
		{
			return (a1 - 1) & 15;
		}
	}
	else
    {
		if (a0 > 0)
		{
			return (a1 == 43) ?  0 : a1 + 1;
		}
		else
		{
			return (a1 ==  0) ? 43 : a1 - 1;
		}
    }
}

/*
 * Described in header
 */
int32_t ml_make_hint(int32_t a0, int32_t a1, int32_t gamma2)
{
	return (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)) ? 1 : 0;
}