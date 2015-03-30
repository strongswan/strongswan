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

#include "aesni_gcm.h"
#include "aesni_key.h"

#include <crypto/iv/iv_gen_seq.h>

#include <tmmintrin.h>

#define NONCE_SIZE 12
#define IV_SIZE 8
#define SALT_SIZE (NONCE_SIZE - IV_SIZE)

/**
 * Parallel pipelining
 */
#define GCM_CRYPT_PARALLELISM 4

typedef struct private_aesni_gcm_t private_aesni_gcm_t;

/**
 * GCM en/decryption method type
 */
typedef void (*aesni_gcm_fn_t)(private_aesni_gcm_t*, size_t, u_char*, u_char*,
							   u_char*, size_t, u_char*, u_char*);

/**
 * Private data of an aesni_gcm_t object.
 */
struct private_aesni_gcm_t {

	/**
	 * Public aesni_gcm_t interface.
	 */
	aesni_gcm_t public;

	/**
	 * Encryption key schedule
	 */
	aesni_key_t *key;

	/**
	 * IV generator.
	 */
	iv_gen_t *iv_gen;

	/**
	 * Length of the integrity check value
	 */
	size_t icv_size;

	/**
	 * Length of the key in bytes
	 */
	size_t key_size;

	/**
	 * GCM encryption function
	 */
	aesni_gcm_fn_t encrypt;

	/**
	 * GCM decryption function
	 */
	aesni_gcm_fn_t decrypt;

	/**
	 * salt to add to nonce
	 */
	u_char salt[SALT_SIZE];

	/**
	 * GHASH subkey H, big-endian
	 */
	__m128i h;
};

/**
 * Byte-swap a 128-bit integer
 */
static inline __m128i swap128(__m128i x)
{
	return _mm_shuffle_epi8(x,
			_mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

/**
 * Multiply two blocks in GF128
 */
static inline __m128i mult_block(__m128i h, __m128i y)
{
	__m128i t1, t2, t3, t4, t5, t6;

	y = swap128(y);

	t1 = _mm_clmulepi64_si128(h, y, 0x00);
	t2 = _mm_clmulepi64_si128(h, y, 0x01);
	t3 = _mm_clmulepi64_si128(h, y, 0x10);
	t4 = _mm_clmulepi64_si128(h, y, 0x11);

	t2 = _mm_xor_si128(t2, t3);
	t3 = _mm_slli_si128(t2, 8);
	t2 = _mm_srli_si128(t2, 8);
	t1 = _mm_xor_si128(t1, t3);
	t4 = _mm_xor_si128(t4, t2);

	t5 = _mm_srli_epi32(t1, 31);
	t1 = _mm_slli_epi32(t1, 1);
	t6 = _mm_srli_epi32(t4, 31);
	t4 = _mm_slli_epi32(t4, 1);

	t3 = _mm_srli_si128(t5, 12);
	t6 = _mm_slli_si128(t6, 4);
	t5 = _mm_slli_si128(t5, 4);
	t1 = _mm_or_si128(t1, t5);
	t4 = _mm_or_si128(t4, t6);
	t4 = _mm_or_si128(t4, t3);

	t5 = _mm_slli_epi32(t1, 31);
	t6 = _mm_slli_epi32(t1, 30);
	t3 = _mm_slli_epi32(t1, 25);

	t5 = _mm_xor_si128(t5, t6);
	t5 = _mm_xor_si128(t5, t3);
	t6 = _mm_srli_si128(t5, 4);
	t4 = _mm_xor_si128(t4, t6);
	t5 = _mm_slli_si128(t5, 12);
	t1 = _mm_xor_si128(t1, t5);
	t4 = _mm_xor_si128(t4, t1);

	t5 = _mm_srli_epi32(t1, 1);
	t2 = _mm_srli_epi32(t1, 2);
	t3 = _mm_srli_epi32(t1, 7);
	t4 = _mm_xor_si128(t4, t2);
	t4 = _mm_xor_si128(t4, t3);
	t4 = _mm_xor_si128(t4, t5);

	return swap128(t4);
}

/**
 * GHASH on a single block
 */
static __m128i ghash(__m128i h, __m128i y, __m128i x)
{
	return mult_block(h, _mm_xor_si128(y, x));
}

/**
 * Start constructing the ICV for the associated data
 */
static __m128i icv_header(private_aesni_gcm_t *this, void *assoc, size_t alen)
{
	u_int blocks, rem, i;
	__m128i y, last, *ab;

	y = _mm_setzero_si128();
	ab = assoc;
	blocks = alen / AES_BLOCK_SIZE;
	rem = alen % AES_BLOCK_SIZE;
	for (i = 0; i < blocks; i++)
	{
		y = ghash(this->h, y, _mm_loadu_si128(ab + i));
	}
	if (rem)
	{
		last = _mm_setzero_si128();
		memcpy(&last, ab + blocks, rem);

		y = ghash(this->h, y, last);
	}

	return y;
}

/**
 * Complete the ICV by hashing a assoc/data length block
 */
static __m128i icv_tailer(private_aesni_gcm_t *this, __m128i y,
						  size_t alen, size_t dlen)
{
	__m128i b;

	htoun64(&b, alen * 8);
	htoun64((u_char*)&b + sizeof(u_int64_t), dlen * 8);

	return ghash(this->h, y, b);
}

/**
 * En-/Decrypt the ICV, trim and store it
 */
static void icv_crypt(private_aesni_gcm_t *this, __m128i y, __m128i j,
					  u_char *icv)
{
	__m128i t, b;
	u_int round;

	t = _mm_xor_si128(j, this->key->schedule[0]);
	for (round = 1; round < this->key->rounds; round++)
	{
		t = _mm_aesenc_si128(t, this->key->schedule[round]);
	}
	t = _mm_aesenclast_si128(t, this->key->schedule[this->key->rounds]);

	t = _mm_xor_si128(y, t);

	_mm_storeu_si128(&b, t);
	memcpy(icv, &b, this->icv_size);
}

/**
 * Do big-endian increment on x
 */
static inline __m128i increment_be(__m128i x)
{
	x = swap128(x);
	x = _mm_add_epi64(x, _mm_set_epi32(0, 0, 0, 1));
	x = swap128(x);

	return x;
}

/**
 * Generate the block J0
 */
static inline __m128i create_j(private_aesni_gcm_t *this, u_char *iv)
{
	u_char j[AES_BLOCK_SIZE];

	memcpy(j, this->salt, SALT_SIZE);
	memcpy(j + SALT_SIZE, iv, IV_SIZE);
	htoun32(j + SALT_SIZE + IV_SIZE, 1);

	return _mm_loadu_si128((__m128i*)j);
}

/**
 * Encrypt a remaining incomplete block, return updated Y
 */
static __m128i encrypt_gcm_rem(private_aesni_gcm_t *this, u_int rem,
							   void *in, void *out, __m128i cb, __m128i y)
{
	__m128i t, b;
	u_int round;

	memset(&b, 0, sizeof(b));
	memcpy(&b, in, rem);

	t = _mm_xor_si128(cb, this->key->schedule[0]);
	for (round = 1; round < this->key->rounds; round++)
	{
		t = _mm_aesenc_si128(t, this->key->schedule[round]);
	}
	t = _mm_aesenclast_si128(t, this->key->schedule[this->key->rounds]);
	b = _mm_xor_si128(t, b);

	memcpy(out, &b, rem);

	memset((u_char*)&b + rem, 0, AES_BLOCK_SIZE - rem);
	return ghash(this->h, y, b);
}

/**
 * Decrypt a remaining incomplete block, return updated Y
 */
static __m128i decrypt_gcm_rem(private_aesni_gcm_t *this, u_int rem,
							   void *in, void *out, __m128i cb, __m128i y)
{
	__m128i t, b;
	u_int round;

	memset(&b, 0, sizeof(b));
	memcpy(&b, in, rem);

	y = ghash(this->h, y, b);

	t = _mm_xor_si128(cb, this->key->schedule[0]);
	for (round = 1; round < this->key->rounds; round++)
	{
		t = _mm_aesenc_si128(t, this->key->schedule[round]);
	}
	t = _mm_aesenclast_si128(t, this->key->schedule[this->key->rounds]);
	b = _mm_xor_si128(t, b);

	memcpy(out, &b, rem);

	return y;
}

/**
 * AES-128 GCM encryption/ICV generation
 */
static void encrypt_gcm128(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);

		t1 = _mm_aesenclast_si128(t1, k10);
		t2 = _mm_aesenclast_si128(t2, k10);
		t3 = _mm_aesenclast_si128(t3, k10);
		t4 = _mm_aesenclast_si128(t4, k10);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);

		y = ghash(this->h, y, t1);
		y = ghash(this->h, y, t2);
		y = ghash(this->h, y, t3);
		y = ghash(this->h, y, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenclast_si128(t1, k10);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		y = ghash(this->h, y, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = encrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

/**
 * AES-128 GCM decryption/ICV generation
 */
static void decrypt_gcm128(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		y = ghash(this->h, y, d1);
		y = ghash(this->h, y, d2);
		y = ghash(this->h, y, d3);
		y = ghash(this->h, y, d4);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);

		t1 = _mm_aesenclast_si128(t1, k10);
		t2 = _mm_aesenclast_si128(t2, k10);
		t3 = _mm_aesenclast_si128(t3, k10);
		t4 = _mm_aesenclast_si128(t4, k10);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		y = ghash(this->h, y, d1);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenclast_si128(t1, k10);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = decrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

/**
 * AES-192 GCM encryption/ICV generation
 */
static void encrypt_gcm192(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];
	k11 = this->key->schedule[11];
	k12 = this->key->schedule[12];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t2 = _mm_aesenc_si128(t2, k10);
		t3 = _mm_aesenc_si128(t3, k10);
		t4 = _mm_aesenc_si128(t4, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t2 = _mm_aesenc_si128(t2, k11);
		t3 = _mm_aesenc_si128(t3, k11);
		t4 = _mm_aesenc_si128(t4, k11);

		t1 = _mm_aesenclast_si128(t1, k12);
		t2 = _mm_aesenclast_si128(t2, k12);
		t3 = _mm_aesenclast_si128(t3, k12);
		t4 = _mm_aesenclast_si128(t4, k12);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);

		y = ghash(this->h, y, t1);
		y = ghash(this->h, y, t2);
		y = ghash(this->h, y, t3);
		y = ghash(this->h, y, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t1 = _mm_aesenclast_si128(t1, k12);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		y = ghash(this->h, y, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = encrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

/**
 * AES-192 GCM decryption/ICV generation
 */
static void decrypt_gcm192(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];
	k11 = this->key->schedule[11];
	k12 = this->key->schedule[12];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		y = ghash(this->h, y, d1);
		y = ghash(this->h, y, d2);
		y = ghash(this->h, y, d3);
		y = ghash(this->h, y, d4);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t2 = _mm_aesenc_si128(t2, k10);
		t3 = _mm_aesenc_si128(t3, k10);
		t4 = _mm_aesenc_si128(t4, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t2 = _mm_aesenc_si128(t2, k11);
		t3 = _mm_aesenc_si128(t3, k11);
		t4 = _mm_aesenc_si128(t4, k11);

		t1 = _mm_aesenclast_si128(t1, k12);
		t2 = _mm_aesenclast_si128(t2, k12);
		t3 = _mm_aesenclast_si128(t3, k12);
		t4 = _mm_aesenclast_si128(t4, k12);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		y = ghash(this->h, y, d1);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t1 = _mm_aesenclast_si128(t1, k12);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = decrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

/**
 * AES-256 GCM encryption/ICV generation
 */
static void encrypt_gcm256(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];
	k11 = this->key->schedule[11];
	k12 = this->key->schedule[12];
	k13 = this->key->schedule[13];
	k14 = this->key->schedule[14];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t2 = _mm_aesenc_si128(t2, k10);
		t3 = _mm_aesenc_si128(t3, k10);
		t4 = _mm_aesenc_si128(t4, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t2 = _mm_aesenc_si128(t2, k11);
		t3 = _mm_aesenc_si128(t3, k11);
		t4 = _mm_aesenc_si128(t4, k11);
		t1 = _mm_aesenc_si128(t1, k12);
		t2 = _mm_aesenc_si128(t2, k12);
		t3 = _mm_aesenc_si128(t3, k12);
		t4 = _mm_aesenc_si128(t4, k12);
		t1 = _mm_aesenc_si128(t1, k13);
		t2 = _mm_aesenc_si128(t2, k13);
		t3 = _mm_aesenc_si128(t3, k13);
		t4 = _mm_aesenc_si128(t4, k13);

		t1 = _mm_aesenclast_si128(t1, k14);
		t2 = _mm_aesenclast_si128(t2, k14);
		t3 = _mm_aesenclast_si128(t3, k14);
		t4 = _mm_aesenclast_si128(t4, k14);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);

		y = ghash(this->h, y, t1);
		y = ghash(this->h, y, t2);
		y = ghash(this->h, y, t3);
		y = ghash(this->h, y, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t1 = _mm_aesenc_si128(t1, k12);
		t1 = _mm_aesenc_si128(t1, k13);
		t1 = _mm_aesenclast_si128(t1, k14);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		y = ghash(this->h, y, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = encrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

/**
 * AES-256 GCM decryption/ICV generation
 */
static void decrypt_gcm256(private_aesni_gcm_t *this,
						   size_t len, u_char *in, u_char *out, u_char *iv,
						   size_t alen, u_char *assoc, u_char *icv)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14;
	__m128i d1, d2, d3, d4, t1, t2, t3, t4;
	__m128i y, j, cb, *bi, *bo;
	u_int blocks, pblocks, rem, i;

	j = create_j(this, iv);
	cb = increment_be(j);
	y = icv_header(this, assoc, alen);
	blocks = len / AES_BLOCK_SIZE;
	pblocks = blocks - (blocks % GCM_CRYPT_PARALLELISM);
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	k0 = this->key->schedule[0];
	k1 = this->key->schedule[1];
	k2 = this->key->schedule[2];
	k3 = this->key->schedule[3];
	k4 = this->key->schedule[4];
	k5 = this->key->schedule[5];
	k6 = this->key->schedule[6];
	k7 = this->key->schedule[7];
	k8 = this->key->schedule[8];
	k9 = this->key->schedule[9];
	k10 = this->key->schedule[10];
	k11 = this->key->schedule[11];
	k12 = this->key->schedule[12];
	k13 = this->key->schedule[13];
	k14 = this->key->schedule[14];

	for (i = 0; i < pblocks; i += GCM_CRYPT_PARALLELISM)
	{
		d1 = _mm_loadu_si128(bi + i + 0);
		d2 = _mm_loadu_si128(bi + i + 1);
		d3 = _mm_loadu_si128(bi + i + 2);
		d4 = _mm_loadu_si128(bi + i + 3);

		y = ghash(this->h, y, d1);
		y = ghash(this->h, y, d2);
		y = ghash(this->h, y, d3);
		y = ghash(this->h, y, d4);

		t1 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t2 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t3 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);
		t4 = _mm_xor_si128(cb, k0);
		cb = increment_be(cb);

		t1 = _mm_aesenc_si128(t1, k1);
		t2 = _mm_aesenc_si128(t2, k1);
		t3 = _mm_aesenc_si128(t3, k1);
		t4 = _mm_aesenc_si128(t4, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t2 = _mm_aesenc_si128(t2, k2);
		t3 = _mm_aesenc_si128(t3, k2);
		t4 = _mm_aesenc_si128(t4, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t2 = _mm_aesenc_si128(t2, k3);
		t3 = _mm_aesenc_si128(t3, k3);
		t4 = _mm_aesenc_si128(t4, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t2 = _mm_aesenc_si128(t2, k4);
		t3 = _mm_aesenc_si128(t3, k4);
		t4 = _mm_aesenc_si128(t4, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t2 = _mm_aesenc_si128(t2, k5);
		t3 = _mm_aesenc_si128(t3, k5);
		t4 = _mm_aesenc_si128(t4, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t2 = _mm_aesenc_si128(t2, k6);
		t3 = _mm_aesenc_si128(t3, k6);
		t4 = _mm_aesenc_si128(t4, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t2 = _mm_aesenc_si128(t2, k7);
		t3 = _mm_aesenc_si128(t3, k7);
		t4 = _mm_aesenc_si128(t4, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t2 = _mm_aesenc_si128(t2, k8);
		t3 = _mm_aesenc_si128(t3, k8);
		t4 = _mm_aesenc_si128(t4, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t2 = _mm_aesenc_si128(t2, k9);
		t3 = _mm_aesenc_si128(t3, k9);
		t4 = _mm_aesenc_si128(t4, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t2 = _mm_aesenc_si128(t2, k10);
		t3 = _mm_aesenc_si128(t3, k10);
		t4 = _mm_aesenc_si128(t4, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t2 = _mm_aesenc_si128(t2, k11);
		t3 = _mm_aesenc_si128(t3, k11);
		t4 = _mm_aesenc_si128(t4, k11);
		t1 = _mm_aesenc_si128(t1, k12);
		t2 = _mm_aesenc_si128(t2, k12);
		t3 = _mm_aesenc_si128(t3, k12);
		t4 = _mm_aesenc_si128(t4, k12);
		t1 = _mm_aesenc_si128(t1, k13);
		t2 = _mm_aesenc_si128(t2, k13);
		t3 = _mm_aesenc_si128(t3, k13);
		t4 = _mm_aesenc_si128(t4, k13);

		t1 = _mm_aesenclast_si128(t1, k14);
		t2 = _mm_aesenclast_si128(t2, k14);
		t3 = _mm_aesenclast_si128(t3, k14);
		t4 = _mm_aesenclast_si128(t4, k14);

		t1 = _mm_xor_si128(t1, d1);
		t2 = _mm_xor_si128(t2, d2);
		t3 = _mm_xor_si128(t3, d3);
		t4 = _mm_xor_si128(t4, d4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
	}

	for (i = pblocks; i < blocks; i++)
	{
		d1 = _mm_loadu_si128(bi + i);

		y = ghash(this->h, y, d1);

		t1 = _mm_xor_si128(cb, k0);
		t1 = _mm_aesenc_si128(t1, k1);
		t1 = _mm_aesenc_si128(t1, k2);
		t1 = _mm_aesenc_si128(t1, k3);
		t1 = _mm_aesenc_si128(t1, k4);
		t1 = _mm_aesenc_si128(t1, k5);
		t1 = _mm_aesenc_si128(t1, k6);
		t1 = _mm_aesenc_si128(t1, k7);
		t1 = _mm_aesenc_si128(t1, k8);
		t1 = _mm_aesenc_si128(t1, k9);
		t1 = _mm_aesenc_si128(t1, k10);
		t1 = _mm_aesenc_si128(t1, k11);
		t1 = _mm_aesenc_si128(t1, k12);
		t1 = _mm_aesenc_si128(t1, k13);
		t1 = _mm_aesenclast_si128(t1, k14);

		t1 = _mm_xor_si128(t1, d1);
		_mm_storeu_si128(bo + i, t1);

		cb = increment_be(cb);
	}

	if (rem)
	{
		y = decrypt_gcm_rem(this, rem, bi + blocks, bo + blocks, cb, y);
	}
	y = icv_tailer(this, y, alen, len);
	icv_crypt(this, y, j, icv);
}

METHOD(aead_t, encrypt, bool,
	private_aesni_gcm_t *this, chunk_t plain, chunk_t assoc, chunk_t iv,
	chunk_t *encr)
{
	u_char *out;

	if (!this->key || iv.len != IV_SIZE)
	{
		return FALSE;
	}
	out = plain.ptr;
	if (encr)
	{
		*encr = chunk_alloc(plain.len + this->icv_size);
		out = encr->ptr;
	}
	this->encrypt(this, plain.len, plain.ptr, out, iv.ptr,
				  assoc.len, assoc.ptr, out + plain.len);
	return TRUE;
}

METHOD(aead_t, decrypt, bool,
	private_aesni_gcm_t *this, chunk_t encr, chunk_t assoc, chunk_t iv,
	chunk_t *plain)
{
	u_char *out, icv[this->icv_size];

	if (!this->key || iv.len != IV_SIZE || encr.len < this->icv_size)
	{
		return FALSE;
	}
	encr.len -= this->icv_size;
	out = encr.ptr;
	if (plain)
	{
		*plain = chunk_alloc(encr.len);
		out = plain->ptr;
	}
	this->decrypt(this, encr.len, encr.ptr, out, iv.ptr,
				  assoc.len, assoc.ptr, icv);
	return memeq_const(icv, encr.ptr + encr.len, this->icv_size);
}

METHOD(aead_t, get_block_size, size_t,
	private_aesni_gcm_t *this)
{
	return 1;
}

METHOD(aead_t, get_icv_size, size_t,
	private_aesni_gcm_t *this)
{
	return this->icv_size;
}

METHOD(aead_t, get_iv_size, size_t,
	private_aesni_gcm_t *this)
{
	return IV_SIZE;
}

METHOD(aead_t, get_iv_gen, iv_gen_t*,
	private_aesni_gcm_t *this)
{
	return this->iv_gen;
}

METHOD(aead_t, get_key_size, size_t,
	private_aesni_gcm_t *this)
{
	return this->key_size + SALT_SIZE;
}

METHOD(aead_t, set_key, bool,
	private_aesni_gcm_t *this, chunk_t key)
{
	u_int round;
	__m128i h;

	if (key.len != this->key_size + SALT_SIZE)
	{
		return FALSE;
	}

	memcpy(this->salt, key.ptr + key.len - SALT_SIZE, SALT_SIZE);
	key.len -= SALT_SIZE;

	DESTROY_IF(this->key);
	this->key = aesni_key_create(TRUE, key);

	h = _mm_xor_si128(_mm_setzero_si128(), this->key->schedule[0]);
	for (round = 1; round < this->key->rounds; round++)
	{
		h = _mm_aesenc_si128(h, this->key->schedule[round]);
	}
	h = _mm_aesenclast_si128(h, this->key->schedule[this->key->rounds]);

	this->h = swap128(h);

	return TRUE;
}

METHOD(aead_t, destroy, void,
	private_aesni_gcm_t *this)
{
	DESTROY_IF(this->key);
	memwipe(&this->h, sizeof(this->h));
	this->iv_gen->destroy(this->iv_gen);
	free(this);
}

/**
 * See header
 */
aesni_gcm_t *aesni_gcm_create(encryption_algorithm_t algo,
							  size_t key_size, size_t salt_size)
{
	private_aesni_gcm_t *this;
	size_t icv_size;

	switch (key_size)
	{
		case 0:
			key_size = 16;
			break;
		case 16:
		case 24:
		case 32:
			break;
		default:
			return NULL;
	}
	if (salt_size && salt_size != SALT_SIZE)
	{
		/* currently not supported */
		return NULL;
	}
	switch (algo)
	{
		case ENCR_AES_GCM_ICV8:
			algo = ENCR_AES_CBC;
			icv_size = 8;
			break;
		case ENCR_AES_GCM_ICV12:
			algo = ENCR_AES_CBC;
			icv_size = 12;
			break;
		case ENCR_AES_GCM_ICV16:
			algo = ENCR_AES_CBC;
			icv_size = 16;
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.aead = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_icv_size = _get_icv_size,
				.get_iv_size = _get_iv_size,
				.get_iv_gen = _get_iv_gen,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.key_size = key_size,
		.iv_gen = iv_gen_seq_create(),
		.icv_size = icv_size,
	);

	switch (key_size)
	{
		case 16:
			this->encrypt = encrypt_gcm128;
			this->decrypt = decrypt_gcm128;
			break;
		case 24:
			this->encrypt = encrypt_gcm192;
			this->decrypt = decrypt_gcm192;
			break;
		case 32:
			this->encrypt = encrypt_gcm256;
			this->decrypt = decrypt_gcm256;
			break;
	}

	return &this->public;
}
