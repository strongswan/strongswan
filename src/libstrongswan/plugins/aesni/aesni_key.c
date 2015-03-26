/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include "aesni_key.h"

/**
 * Rounds used for each AES key size
 */
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12

typedef struct private_aesni_key_t private_aesni_key_t;

/**
 * Private data of an aesni_key_t object.
 */
struct private_aesni_key_t {

	/**
	 * Public aesni_key_t interface.
	 */
	aesni_key_t public;
};

/**
 * Invert round encryption keys to get a decryption key schedule
 */
static void reverse_key(aesni_key_t *this)
{
	__m128i t[this->rounds + 1];
	int i;

	for (i = 0; i <= this->rounds; i++)
	{
		t[i] = this->schedule[i];
	}
	this->schedule[this->rounds] = t[0];
	for (i = 1; i < this->rounds; i++)
	{
		this->schedule[this->rounds - i] = _mm_aesimc_si128(t[i]);
	}
	this->schedule[0] = t[this->rounds];

	memwipe(t, sizeof(t));
}

/**
 * Assist in creating a 128-bit round key
 */
static __m128i assist128(__m128i a, __m128i b)
{
	__m128i c;

	b = _mm_shuffle_epi32(b ,0xff);
	c = _mm_slli_si128(a, 0x04);
	a = _mm_xor_si128(a, c);
	c = _mm_slli_si128(c, 0x04);
	a = _mm_xor_si128(a, c);
	c = _mm_slli_si128(c, 0x04);
	a = _mm_xor_si128(a, c);
	a = _mm_xor_si128(a, b);

	return a;
}

/**
 * Expand a 128-bit key to encryption round keys
 */
static void expand128(__m128i *key, __m128i *schedule)
{
	__m128i t;

	schedule[0] = t = _mm_loadu_si128(key);
	schedule[1] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x01));
	schedule[2] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x02));
	schedule[3] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x04));
	schedule[4] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x08));
	schedule[5] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x10));
	schedule[6] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x20));
	schedule[7] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x40));
	schedule[8] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x80));
	schedule[9] = t = assist128(t, _mm_aeskeygenassist_si128(t, 0x1b));
	schedule[10]    = assist128(t, _mm_aeskeygenassist_si128(t, 0x36));
}

/**
 * Assist in creating a 192-bit round key
 */
static __m128i assist192(__m128i b, __m128i c, __m128i *a)
{
	__m128i t;

	 b = _mm_shuffle_epi32(b, 0x55);
	 t = _mm_slli_si128(*a, 0x04);
	*a = _mm_xor_si128(*a, t);
	 t = _mm_slli_si128(t, 0x04);
	*a = _mm_xor_si128(*a, t);
	 t = _mm_slli_si128(t, 0x04);
	*a = _mm_xor_si128(*a, t);
	*a = _mm_xor_si128(*a, b);
	 b = _mm_shuffle_epi32(*a, 0xff);
	 t = _mm_slli_si128(c, 0x04);
	 t = _mm_xor_si128(c, t);
	 t = _mm_xor_si128(t, b);

	return t;
}

/**
 * return a[63:0] | b[63:0] << 64
 */
static __m128i _mm_shuffle_i00(__m128i a, __m128i b)
{
	return (__m128i)_mm_shuffle_pd((__m128d)a, (__m128d)b, 0);
}

/**
 * return a[127:64] >> 64 | b[63:0] << 64
 */
static __m128i _mm_shuffle_i01(__m128i a, __m128i b)
{
	return (__m128i)_mm_shuffle_pd((__m128d)a, (__m128d)b, 1);
}

/**
 * Expand a 192-bit encryption key to round keys
 */
static void expand192(__m128i *key, __m128i *schedule)
{
	__m128i t1, t2, t3;

	schedule[0] = t1 = _mm_loadu_si128(key);
	t2 = t3 = _mm_loadu_si128(key + 1);

	t2 = assist192(_mm_aeskeygenassist_si128(t2, 0x1), t2, &t1);
	schedule[1] = _mm_shuffle_i00(t3, t1);
	schedule[2] = _mm_shuffle_i01(t1, t2);
	t2 = t3 = assist192(_mm_aeskeygenassist_si128(t2, 0x2), t2, &t1);
	schedule[3] = t1;

	t2 = assist192(_mm_aeskeygenassist_si128(t2, 0x4), t2, &t1);
	schedule[4] = _mm_shuffle_i00(t3, t1);
	schedule[5] = _mm_shuffle_i01(t1, t2);
	t2 = t3 = assist192(_mm_aeskeygenassist_si128(t2, 0x8), t2, &t1);
	schedule[6] = t1;

	t2 = assist192(_mm_aeskeygenassist_si128 (t2,0x10), t2, &t1);
	schedule[7] = _mm_shuffle_i00(t3, t1);
	schedule[8] = _mm_shuffle_i01(t1, t2);
	t2 = t3 = assist192(_mm_aeskeygenassist_si128 (t2,0x20), t2, &t1);
	schedule[9] = t1;

	t2 = assist192(_mm_aeskeygenassist_si128(t2, 0x40), t2, &t1);
	schedule[10] = _mm_shuffle_i00(t3, t1);
	schedule[11] = _mm_shuffle_i01(t1, t2);
	assist192(_mm_aeskeygenassist_si128(t2, 0x80), t2, &t1);
	schedule[12] = t1;
}

METHOD(aesni_key_t, destroy, void,
	private_aesni_key_t *this)
{
	memwipe(this, sizeof(*this) + (this->public.rounds + 1) * AES_BLOCK_SIZE);
	free(this);
}

/**
 * See header
 */
aesni_key_t *aesni_key_create(bool encrypt, chunk_t key)
{
	private_aesni_key_t *this;
	int rounds;

	switch (key.len)
	{
		case 16:
			rounds = AES128_ROUNDS;
			break;
		case 24:
			rounds = AES192_ROUNDS;
			break;
		default:
			return NULL;
	}

	INIT_EXTRA(this, (rounds + 1) * AES_BLOCK_SIZE,
		.public = {
			.destroy = _destroy,
			.rounds = rounds,
		},
	);

	switch (key.len)
	{
		case 16:
			expand128((__m128i*)key.ptr, this->public.schedule);
			break;
		case 24:
			expand192((__m128i*)key.ptr, this->public.schedule);
			break;
		default:
			break;
	}

	if (!encrypt)
	{
		reverse_key(&this->public);
	}

	return &this->public;
}
