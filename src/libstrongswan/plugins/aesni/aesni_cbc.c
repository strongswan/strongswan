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

#include "aesni_cbc.h"
#include "aesni_key.h"

/**
 * Pipeline parallelism we use for CBC decryption
 */
#define CBC_DECRYPT_PARALLELISM 4

typedef struct private_aesni_cbc_t private_aesni_cbc_t;

/**
 * CBC en/decryption method type
 */
typedef void (*aesni_cbc_fn_t)(aesni_key_t*, u_int, u_char*, u_char*, u_char*);

/**
 * Private data of an aesni_cbc_t object.
 */
struct private_aesni_cbc_t {

	/**
	 * Public aesni_cbc_t interface.
	 */
	aesni_cbc_t public;

	/**
	 * Key size
	 */
	u_int key_size;

	/**
	 * Encryption key schedule
	 */
	aesni_key_t *ekey;

	/**
	 * Decryption key schedule
	 */
	aesni_key_t *dkey;

	/**
	 * Encryption method
	 */
	aesni_cbc_fn_t encrypt;

	/**
	 * Decryption method
	 */
	aesni_cbc_fn_t decrypt;
};

/**
 * AES-128 CBC encryption
 */
static void encrypt_cbc128(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;
	__m128i t, fb, *bi, *bo;
	int i;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];

	bi = (__m128i*)in;
	bo = (__m128i*)out;

	fb = _mm_loadu_si128((__m128i*)iv);
	for (i = 0; i < blocks; i++)
	{
		t = _mm_loadu_si128(bi + i);
		fb = _mm_xor_si128(t, fb);
		fb = _mm_xor_si128(fb, k0);

		fb = _mm_aesenc_si128(fb, k1);
		fb = _mm_aesenc_si128(fb, k2);
		fb = _mm_aesenc_si128(fb, k3);
		fb = _mm_aesenc_si128(fb, k4);
		fb = _mm_aesenc_si128(fb, k5);
		fb = _mm_aesenc_si128(fb, k6);
		fb = _mm_aesenc_si128(fb, k7);
		fb = _mm_aesenc_si128(fb, k8);
		fb = _mm_aesenc_si128(fb, k9);

		fb = _mm_aesenclast_si128(fb, k10);
		_mm_storeu_si128(bo + i, fb);
	}
}

/**
 * AES-128 CBC decryption
 */
static void decrypt_cbc128(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;
	__m128i last, *bi, *bo;
	__m128i t1, t2, t3, t4;
	__m128i f1, f2, f3, f4;
	u_int i, pblocks;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];

	bi = (__m128i*)in;
	bo = (__m128i*)out;
	pblocks = blocks - (blocks % CBC_DECRYPT_PARALLELISM);

	f1 = _mm_loadu_si128((__m128i*)iv);

	for (i = 0; i < pblocks; i += CBC_DECRYPT_PARALLELISM)
	{
		t1 = _mm_loadu_si128(bi + i + 0);
		t2 = _mm_loadu_si128(bi + i + 1);
		t3 = _mm_loadu_si128(bi + i + 2);
		t4 = _mm_loadu_si128(bi + i + 3);

		f2 = t1;
		f3 = t2;
		f4 = t3;
		last = t4;

		t1 = _mm_xor_si128(t1, k0);
		t2 = _mm_xor_si128(t2, k0);
		t3 = _mm_xor_si128(t3, k0);
		t4 = _mm_xor_si128(t4, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t2 = _mm_aesdec_si128(t2, k1);
		t3 = _mm_aesdec_si128(t3, k1);
		t4 = _mm_aesdec_si128(t4, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t2 = _mm_aesdec_si128(t2, k2);
		t3 = _mm_aesdec_si128(t3, k2);
		t4 = _mm_aesdec_si128(t4, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t2 = _mm_aesdec_si128(t2, k3);
		t3 = _mm_aesdec_si128(t3, k3);
		t4 = _mm_aesdec_si128(t4, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t2 = _mm_aesdec_si128(t2, k4);
		t3 = _mm_aesdec_si128(t3, k4);
		t4 = _mm_aesdec_si128(t4, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t2 = _mm_aesdec_si128(t2, k5);
		t3 = _mm_aesdec_si128(t3, k5);
		t4 = _mm_aesdec_si128(t4, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t2 = _mm_aesdec_si128(t2, k6);
		t3 = _mm_aesdec_si128(t3, k6);
		t4 = _mm_aesdec_si128(t4, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t2 = _mm_aesdec_si128(t2, k7);
		t3 = _mm_aesdec_si128(t3, k7);
		t4 = _mm_aesdec_si128(t4, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t2 = _mm_aesdec_si128(t2, k8);
		t3 = _mm_aesdec_si128(t3, k8);
		t4 = _mm_aesdec_si128(t4, k8);
		t1 = _mm_aesdec_si128(t1, k9);
		t2 = _mm_aesdec_si128(t2, k9);
		t3 = _mm_aesdec_si128(t3, k9);
		t4 = _mm_aesdec_si128(t4, k9);

		t1 = _mm_aesdeclast_si128(t1, k10);
		t2 = _mm_aesdeclast_si128(t2, k10);
		t3 = _mm_aesdeclast_si128(t3, k10);
		t4 = _mm_aesdeclast_si128(t4, k10);
		t1 = _mm_xor_si128(t1, f1);
		t2 = _mm_xor_si128(t2, f2);
		t3 = _mm_xor_si128(t3, f3);
		t4 = _mm_xor_si128(t4, f4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
		f1 = last;
	}

	for (i = pblocks; i < blocks; i++)
	{
		last = _mm_loadu_si128(bi + i);
		t1 = _mm_xor_si128(last, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t1 = _mm_aesdec_si128(t1, k9);

		t1 = _mm_aesdeclast_si128(t1, k10);
		t1 = _mm_xor_si128(t1, f1);
		_mm_storeu_si128(bo + i, t1);
		f1 = last;
	}
}

/**
 * AES-192 CBC encryption
 */
static void encrypt_cbc192(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12;
	__m128i t, fb, *bi, *bo;
	int i;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];
	k11 = key->schedule[11];
	k12 = key->schedule[12];

	bi = (__m128i*)in;
	bo = (__m128i*)out;

	fb = _mm_loadu_si128((__m128i*)iv);
	for (i = 0; i < blocks; i++)
	{
		t = _mm_loadu_si128(bi + i);
		fb = _mm_xor_si128(t, fb);
		fb = _mm_xor_si128(fb, k0);

		fb = _mm_aesenc_si128(fb, k1);
		fb = _mm_aesenc_si128(fb, k2);
		fb = _mm_aesenc_si128(fb, k3);
		fb = _mm_aesenc_si128(fb, k4);
		fb = _mm_aesenc_si128(fb, k5);
		fb = _mm_aesenc_si128(fb, k6);
		fb = _mm_aesenc_si128(fb, k7);
		fb = _mm_aesenc_si128(fb, k8);
		fb = _mm_aesenc_si128(fb, k9);
		fb = _mm_aesenc_si128(fb, k10);
		fb = _mm_aesenc_si128(fb, k11);

		fb = _mm_aesenclast_si128(fb, k12);
		_mm_storeu_si128(bo + i, fb);
	}
}

/**
 * AES-192 CBC decryption
 */
static void decrypt_cbc192(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12;
	__m128i last, *bi, *bo;
	__m128i t1, t2, t3, t4;
	__m128i f1, f2, f3, f4;
	u_int i, pblocks;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];
	k11 = key->schedule[11];
	k12 = key->schedule[12];

	bi = (__m128i*)in;
	bo = (__m128i*)out;
	pblocks = blocks - (blocks % CBC_DECRYPT_PARALLELISM);

	f1 = _mm_loadu_si128((__m128i*)iv);

	for (i = 0; i < pblocks; i += CBC_DECRYPT_PARALLELISM)
	{
		t1 = _mm_loadu_si128(bi + i + 0);
		t2 = _mm_loadu_si128(bi + i + 1);
		t3 = _mm_loadu_si128(bi + i + 2);
		t4 = _mm_loadu_si128(bi + i + 3);

		f2 = t1;
		f3 = t2;
		f4 = t3;
		last = t4;

		t1 = _mm_xor_si128(t1, k0);
		t2 = _mm_xor_si128(t2, k0);
		t3 = _mm_xor_si128(t3, k0);
		t4 = _mm_xor_si128(t4, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t2 = _mm_aesdec_si128(t2, k1);
		t3 = _mm_aesdec_si128(t3, k1);
		t4 = _mm_aesdec_si128(t4, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t2 = _mm_aesdec_si128(t2, k2);
		t3 = _mm_aesdec_si128(t3, k2);
		t4 = _mm_aesdec_si128(t4, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t2 = _mm_aesdec_si128(t2, k3);
		t3 = _mm_aesdec_si128(t3, k3);
		t4 = _mm_aesdec_si128(t4, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t2 = _mm_aesdec_si128(t2, k4);
		t3 = _mm_aesdec_si128(t3, k4);
		t4 = _mm_aesdec_si128(t4, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t2 = _mm_aesdec_si128(t2, k5);
		t3 = _mm_aesdec_si128(t3, k5);
		t4 = _mm_aesdec_si128(t4, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t2 = _mm_aesdec_si128(t2, k6);
		t3 = _mm_aesdec_si128(t3, k6);
		t4 = _mm_aesdec_si128(t4, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t2 = _mm_aesdec_si128(t2, k7);
		t3 = _mm_aesdec_si128(t3, k7);
		t4 = _mm_aesdec_si128(t4, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t2 = _mm_aesdec_si128(t2, k8);
		t3 = _mm_aesdec_si128(t3, k8);
		t4 = _mm_aesdec_si128(t4, k8);
		t1 = _mm_aesdec_si128(t1, k9);
		t2 = _mm_aesdec_si128(t2, k9);
		t3 = _mm_aesdec_si128(t3, k9);
		t4 = _mm_aesdec_si128(t4, k9);
		t1 = _mm_aesdec_si128(t1, k10);
		t2 = _mm_aesdec_si128(t2, k10);
		t3 = _mm_aesdec_si128(t3, k10);
		t4 = _mm_aesdec_si128(t4, k10);
		t1 = _mm_aesdec_si128(t1, k11);
		t2 = _mm_aesdec_si128(t2, k11);
		t3 = _mm_aesdec_si128(t3, k11);
		t4 = _mm_aesdec_si128(t4, k11);

		t1 = _mm_aesdeclast_si128(t1, k12);
		t2 = _mm_aesdeclast_si128(t2, k12);
		t3 = _mm_aesdeclast_si128(t3, k12);
		t4 = _mm_aesdeclast_si128(t4, k12);
		t1 = _mm_xor_si128(t1, f1);
		t2 = _mm_xor_si128(t2, f2);
		t3 = _mm_xor_si128(t3, f3);
		t4 = _mm_xor_si128(t4, f4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
		f1 = last;
	}

	for (i = pblocks; i < blocks; i++)
	{
		last = _mm_loadu_si128(bi + i);
		t1 = _mm_xor_si128(last, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t1 = _mm_aesdec_si128(t1, k9);
		t1 = _mm_aesdec_si128(t1, k10);
		t1 = _mm_aesdec_si128(t1, k11);

		t1 = _mm_aesdeclast_si128(t1, k12);
		t1 = _mm_xor_si128(t1, f1);
		_mm_storeu_si128(bo + i, t1);
		f1 = last;
	}
}

/**
 * AES-256 CBC encryption
 */
static void encrypt_cbc256(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14;
	__m128i t, fb, *bi, *bo;
	int i;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];
	k11 = key->schedule[11];
	k12 = key->schedule[12];
	k13 = key->schedule[13];
	k14 = key->schedule[14];

	bi = (__m128i*)in;
	bo = (__m128i*)out;

	fb = _mm_loadu_si128((__m128i*)iv);
	for (i = 0; i < blocks; i++)
	{
		t = _mm_loadu_si128(bi + i);
		fb = _mm_xor_si128(t, fb);
		fb = _mm_xor_si128(fb, k0);

		fb = _mm_aesenc_si128(fb, k1);
		fb = _mm_aesenc_si128(fb, k2);
		fb = _mm_aesenc_si128(fb, k3);
		fb = _mm_aesenc_si128(fb, k4);
		fb = _mm_aesenc_si128(fb, k5);
		fb = _mm_aesenc_si128(fb, k6);
		fb = _mm_aesenc_si128(fb, k7);
		fb = _mm_aesenc_si128(fb, k8);
		fb = _mm_aesenc_si128(fb, k9);
		fb = _mm_aesenc_si128(fb, k10);
		fb = _mm_aesenc_si128(fb, k11);
		fb = _mm_aesenc_si128(fb, k12);
		fb = _mm_aesenc_si128(fb, k13);

		fb = _mm_aesenclast_si128(fb, k14);
		_mm_storeu_si128(bo + i, fb);
	}
}

/**
 * AES-256 CBC decryption
 */
static void decrypt_cbc256(aesni_key_t *key, u_int blocks, u_char *in,
						   u_char *iv, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14;
	__m128i last, *bi, *bo;
	__m128i t1, t2, t3, t4;
	__m128i f1, f2, f3, f4;
	u_int i, pblocks;

	k0 = key->schedule[0];
	k1 = key->schedule[1];
	k2 = key->schedule[2];
	k3 = key->schedule[3];
	k4 = key->schedule[4];
	k5 = key->schedule[5];
	k6 = key->schedule[6];
	k7 = key->schedule[7];
	k8 = key->schedule[8];
	k9 = key->schedule[9];
	k10 = key->schedule[10];
	k11 = key->schedule[11];
	k12 = key->schedule[12];
	k13 = key->schedule[13];
	k14 = key->schedule[14];

	bi = (__m128i*)in;
	bo = (__m128i*)out;
	pblocks = blocks - (blocks % CBC_DECRYPT_PARALLELISM);

	f1 = _mm_loadu_si128((__m128i*)iv);

	for (i = 0; i < pblocks; i += CBC_DECRYPT_PARALLELISM)
	{
		t1 = _mm_loadu_si128(bi + i + 0);
		t2 = _mm_loadu_si128(bi + i + 1);
		t3 = _mm_loadu_si128(bi + i + 2);
		t4 = _mm_loadu_si128(bi + i + 3);

		f2 = t1;
		f3 = t2;
		f4 = t3;
		last = t4;

		t1 = _mm_xor_si128(t1, k0);
		t2 = _mm_xor_si128(t2, k0);
		t3 = _mm_xor_si128(t3, k0);
		t4 = _mm_xor_si128(t4, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t2 = _mm_aesdec_si128(t2, k1);
		t3 = _mm_aesdec_si128(t3, k1);
		t4 = _mm_aesdec_si128(t4, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t2 = _mm_aesdec_si128(t2, k2);
		t3 = _mm_aesdec_si128(t3, k2);
		t4 = _mm_aesdec_si128(t4, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t2 = _mm_aesdec_si128(t2, k3);
		t3 = _mm_aesdec_si128(t3, k3);
		t4 = _mm_aesdec_si128(t4, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t2 = _mm_aesdec_si128(t2, k4);
		t3 = _mm_aesdec_si128(t3, k4);
		t4 = _mm_aesdec_si128(t4, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t2 = _mm_aesdec_si128(t2, k5);
		t3 = _mm_aesdec_si128(t3, k5);
		t4 = _mm_aesdec_si128(t4, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t2 = _mm_aesdec_si128(t2, k6);
		t3 = _mm_aesdec_si128(t3, k6);
		t4 = _mm_aesdec_si128(t4, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t2 = _mm_aesdec_si128(t2, k7);
		t3 = _mm_aesdec_si128(t3, k7);
		t4 = _mm_aesdec_si128(t4, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t2 = _mm_aesdec_si128(t2, k8);
		t3 = _mm_aesdec_si128(t3, k8);
		t4 = _mm_aesdec_si128(t4, k8);
		t1 = _mm_aesdec_si128(t1, k9);
		t2 = _mm_aesdec_si128(t2, k9);
		t3 = _mm_aesdec_si128(t3, k9);
		t4 = _mm_aesdec_si128(t4, k9);
		t1 = _mm_aesdec_si128(t1, k10);
		t2 = _mm_aesdec_si128(t2, k10);
		t3 = _mm_aesdec_si128(t3, k10);
		t4 = _mm_aesdec_si128(t4, k10);
		t1 = _mm_aesdec_si128(t1, k11);
		t2 = _mm_aesdec_si128(t2, k11);
		t3 = _mm_aesdec_si128(t3, k11);
		t4 = _mm_aesdec_si128(t4, k11);
		t1 = _mm_aesdec_si128(t1, k12);
		t2 = _mm_aesdec_si128(t2, k12);
		t3 = _mm_aesdec_si128(t3, k12);
		t4 = _mm_aesdec_si128(t4, k12);
		t1 = _mm_aesdec_si128(t1, k13);
		t2 = _mm_aesdec_si128(t2, k13);
		t3 = _mm_aesdec_si128(t3, k13);
		t4 = _mm_aesdec_si128(t4, k13);

		t1 = _mm_aesdeclast_si128(t1, k14);
		t2 = _mm_aesdeclast_si128(t2, k14);
		t3 = _mm_aesdeclast_si128(t3, k14);
		t4 = _mm_aesdeclast_si128(t4, k14);
		t1 = _mm_xor_si128(t1, f1);
		t2 = _mm_xor_si128(t2, f2);
		t3 = _mm_xor_si128(t3, f3);
		t4 = _mm_xor_si128(t4, f4);
		_mm_storeu_si128(bo + i + 0, t1);
		_mm_storeu_si128(bo + i + 1, t2);
		_mm_storeu_si128(bo + i + 2, t3);
		_mm_storeu_si128(bo + i + 3, t4);
		f1 = last;
	}

	for (i = pblocks; i < blocks; i++)
	{
		last = _mm_loadu_si128(bi + i);
		t1 = _mm_xor_si128(last, k0);

		t1 = _mm_aesdec_si128(t1, k1);
		t1 = _mm_aesdec_si128(t1, k2);
		t1 = _mm_aesdec_si128(t1, k3);
		t1 = _mm_aesdec_si128(t1, k4);
		t1 = _mm_aesdec_si128(t1, k5);
		t1 = _mm_aesdec_si128(t1, k6);
		t1 = _mm_aesdec_si128(t1, k7);
		t1 = _mm_aesdec_si128(t1, k8);
		t1 = _mm_aesdec_si128(t1, k9);
		t1 = _mm_aesdec_si128(t1, k10);
		t1 = _mm_aesdec_si128(t1, k11);
		t1 = _mm_aesdec_si128(t1, k12);
		t1 = _mm_aesdec_si128(t1, k13);

		t1 = _mm_aesdeclast_si128(t1, k14);
		t1 = _mm_xor_si128(t1, f1);
		_mm_storeu_si128(bo + i, t1);
		f1 = last;
	}
}

/**
 * Do inline or allocated de/encryption using key schedule
 */
static bool crypt(aesni_cbc_fn_t fn, aesni_key_t *key,
				  chunk_t data, chunk_t iv, chunk_t *out)
{
	u_char *buf;

	if (!key || iv.len != AES_BLOCK_SIZE || data.len % AES_BLOCK_SIZE)
	{
		return FALSE;
	}
	if (out)
	{
		*out = chunk_alloc(data.len);
		buf = out->ptr;
	}
	else
	{
		buf = data.ptr;
	}
	fn(key, data.len / AES_BLOCK_SIZE, data.ptr, iv.ptr, buf);
	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	private_aesni_cbc_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	return crypt(this->encrypt, this->ekey, data, iv, encrypted);
}

METHOD(crypter_t, decrypt, bool,
	private_aesni_cbc_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	return crypt(this->decrypt, this->dkey, data, iv, decrypted);
}

METHOD(crypter_t, get_block_size, size_t,
	private_aesni_cbc_t *this)
{
	return AES_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_aesni_cbc_t *this)
{
	return AES_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
	private_aesni_cbc_t *this)
{
	return this->key_size;
}

METHOD(crypter_t, set_key, bool,
	private_aesni_cbc_t *this, chunk_t key)
{
	if (key.len != this->key_size)
	{
		return FALSE;
	}

	DESTROY_IF(this->ekey);
	DESTROY_IF(this->dkey);

	this->ekey = aesni_key_create(TRUE, key);
	this->dkey = aesni_key_create(FALSE, key);

	return this->ekey && this->dkey;
}

METHOD(crypter_t, destroy, void,
	private_aesni_cbc_t *this)
{
	DESTROY_IF(this->ekey);
	DESTROY_IF(this->dkey);
	free_align(this);
}

/**
 * See header
 */
aesni_cbc_t *aesni_cbc_create(encryption_algorithm_t algo, size_t key_size)
{
	private_aesni_cbc_t *this;

	if (algo != ENCR_AES_CBC)
	{
		return NULL;
	}
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

	INIT_ALIGN(this, sizeof(__m128i),
		.public = {
			.crypter = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.key_size = key_size,
	);

	switch (key_size)
	{
		case 16:
			this->encrypt = encrypt_cbc128;
			this->decrypt = decrypt_cbc128;
			break;
		case 24:
			this->encrypt = encrypt_cbc192;
			this->decrypt = decrypt_cbc192;
			break;
		case 32:
			this->encrypt = encrypt_cbc256;
			this->decrypt = decrypt_cbc256;
			break;
	}

	return &this->public;
}
