/*
 * Copyright (C) 2026 Tobias Brunner
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
 * @defgroup constant_time_i constant_time
 * @{ @ingroup constant_time_i
 */

#ifndef CONSTANT_TIME_H_
#define CONSTANT_TIME_H_

#include <stdint.h>

/**
 * Check if the given values are not equal in constant time.
 *
 * @param x		first value to check
 * @param y		second value to check
 * @return		1 if values are not equal, 0 otherwise
 */
static inline u_int constant_time_neq(uint32_t x, uint32_t y)
{
	return ((x-y) | (y-x)) >> 31;
}

/**
 * Check if the given values are equal in constant time.
 *
 * @param x		first value to check
 * @param y		second value to check
 * @return		1 if values are equal, 0 otherwise
 */
static inline u_int constant_time_eq(uint32_t x, uint32_t y)
{
	return 1 ^ constant_time_neq(x, y);
}

/**
 * Compare the two values and return 1 if the first argument is lower than
 * the second in constant time.
 *
 * @param x		first value to check
 * @param y		second value to check
 * @return		1 if first value is lower than second
 */
static inline u_int constant_time_lt(uint32_t x, uint32_t y)
{
	return (x ^ ((x^y) | ((x-y) ^ y))) >> 31;
}

/**
 * Compare the two values and return 1 if the first argument greater or equal to
 * the second in constant time.
 *
 * @param x		first value to check
 * @param y		second value to check
 * @return		1 if first value is greater or equal to the second
 */
static inline u_int constant_time_ge(uint32_t x, uint32_t y)
{
	return 1 ^ constant_time_lt(x, y);
}

/**
 * Return a 32-bit all bit-set mask if the given value is not 0.
 *
 * @param x		value to check
 * @return		0xffffffff if value is != 0, 0 otherwise
 */
static inline uint32_t constant_time_mask(uint32_t x)
{
	return -(uint32_t)constant_time_neq(x, 0);
}

/**
 * Select one of two values depending on whether the condition is != 0 or not.
 * Basically equivalent to 'c ? x : y'.
 *
 * @param x		first value to select
 * @param y		second value to select
 * @param c		condition
 * @return		x if c is != 0, y otherwise
 */
static inline uint32_t constant_time_select(uint32_t x, uint32_t y, uint32_t c)
{
	uint32_t m = constant_time_mask(c);
	return (x & m) | (y & ~m);
}

#endif /** CONSTANT_TIME_H_ @} */
