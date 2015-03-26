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

#include "aesni_ctr.h"
#include "aesni_key.h"

#include <tmmintrin.h>

typedef struct private_aesni_ctr_t private_aesni_ctr_t;

/**
 * CTR en/decryption method type
 */
typedef void (*aesni_ctr_fn_t)(private_aesni_ctr_t*, size_t, u_char*, u_char*);

/**
 * Private data of an aesni_ctr_t object.
 */
struct private_aesni_ctr_t {

	/**
	 * Public aesni_ctr_t interface.
	 */
	aesni_ctr_t public;

	/**
	 * Key size
	 */
	u_int key_size;

	/**
	 * Key schedule
	 */
	aesni_key_t *key;

	/**
	 * Encryption method
	 */
	aesni_ctr_fn_t crypt;

	/**
	 * Counter state
	 */
	struct {
		char nonce[4];
		char iv[8];
		u_int32_t counter;
	} __attribute__((packed, aligned(sizeof(__m128i)))) state;
};

/**
 * Do big-endian increment on x
 */
static inline __m128i increment_be(__m128i x)
{
	__m128i swap;

	swap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

	x = _mm_shuffle_epi8(x, swap);
	x = _mm_add_epi64(x, _mm_set_epi32(0, 0, 0, 1));
	x = _mm_shuffle_epi8(x, swap);

	return x;
}

/**
 * AES-128 CTR encryption
 */
static void encrypt_ctr128(private_aesni_ctr_t *this,
						   size_t len, u_char *in, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;
	__m128i state, t, d, b, *bi, *bo;
	u_int i, blocks, rem;

	state = _mm_load_si128((__m128i*)&this->state);
	blocks = len / AES_BLOCK_SIZE;
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

	for (i = 0; i < blocks; i++)
	{
		d = _mm_loadu_si128(bi + i);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);

		t = _mm_aesenclast_si128(t, k10);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(bo + i, t);

		state = increment_be(state);
	}

	if (rem)
	{
		memset(&b, 0, sizeof(b));
		memcpy(&b, bi + blocks, rem);

		d = _mm_loadu_si128(&b);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);

		t = _mm_aesenclast_si128(t, k10);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(&b, t);

		memcpy(bo + blocks, &b, rem);
	}
}

/**
 * AES-192 CTR encryption
 */
static void encrypt_ctr192(private_aesni_ctr_t *this,
						   size_t len, u_char *in, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12;
	__m128i state, t, d, b, *bi, *bo;
	u_int i, blocks, rem;

	state = _mm_load_si128((__m128i*)&this->state);
	blocks = len / AES_BLOCK_SIZE;
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

	for (i = 0; i < blocks; i++)
	{
		d = _mm_loadu_si128(bi + i);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);
		t = _mm_aesenc_si128(t, k10);
		t = _mm_aesenc_si128(t, k11);

		t = _mm_aesenclast_si128(t, k12);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(bo + i, t);

		state = increment_be(state);
	}

	if (rem)
	{
		memset(&b, 0, sizeof(b));
		memcpy(&b, bi + blocks, rem);

		d = _mm_loadu_si128(&b);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);
		t = _mm_aesenc_si128(t, k10);
		t = _mm_aesenc_si128(t, k11);

		t = _mm_aesenclast_si128(t, k12);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(&b, t);

		memcpy(bo + blocks, &b, rem);
	}
}

/**
 * AES-256 CTR encryption
 */
static void encrypt_ctr256(private_aesni_ctr_t *this,
						   size_t len, u_char *in, u_char *out)
{
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14;
	__m128i state, t, d, b, *bi, *bo;
	u_int i, blocks, rem;

	state = _mm_load_si128((__m128i*)&this->state);
	blocks = len / AES_BLOCK_SIZE;
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

	for (i = 0; i < blocks; i++)
	{
		d = _mm_loadu_si128(bi + i);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);
		t = _mm_aesenc_si128(t, k10);
		t = _mm_aesenc_si128(t, k11);
		t = _mm_aesenc_si128(t, k12);
		t = _mm_aesenc_si128(t, k13);

		t = _mm_aesenclast_si128(t, k14);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(bo + i, t);

		state = increment_be(state);
	}

	if (rem)
	{
		memset(&b, 0, sizeof(b));
		memcpy(&b, bi + blocks, rem);

		d = _mm_loadu_si128(&b);
		t = _mm_xor_si128(state, k0);

		t = _mm_aesenc_si128(t, k1);
		t = _mm_aesenc_si128(t, k2);
		t = _mm_aesenc_si128(t, k3);
		t = _mm_aesenc_si128(t, k4);
		t = _mm_aesenc_si128(t, k5);
		t = _mm_aesenc_si128(t, k6);
		t = _mm_aesenc_si128(t, k7);
		t = _mm_aesenc_si128(t, k8);
		t = _mm_aesenc_si128(t, k9);
		t = _mm_aesenc_si128(t, k10);
		t = _mm_aesenc_si128(t, k11);
		t = _mm_aesenc_si128(t, k12);
		t = _mm_aesenc_si128(t, k13);

		t = _mm_aesenclast_si128(t, k14);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(&b, t);

		memcpy(bo + blocks, &b, rem);
	}
}

METHOD(crypter_t, crypt, bool,
	private_aesni_ctr_t *this, chunk_t in, chunk_t iv, chunk_t *out)
{
	u_char *buf;

	if (!this->key || iv.len != sizeof(this->state.iv))
	{
		return FALSE;
	}
	memcpy(this->state.iv, iv.ptr, sizeof(this->state.iv));
	this->state.counter = htonl(1);

	buf = in.ptr;
	if (out)
	{
		*out = chunk_alloc(in.len);
		buf = out->ptr;
	}
	this->crypt(this, in.len, in.ptr, buf);
	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_aesni_ctr_t *this)
{
	return 1;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_aesni_ctr_t *this)
{
	return sizeof(this->state.iv);
}

METHOD(crypter_t, get_key_size, size_t,
	private_aesni_ctr_t *this)
{
	return this->key_size + sizeof(this->state.nonce);
}

METHOD(crypter_t, set_key, bool,
	private_aesni_ctr_t *this, chunk_t key)
{
	if (key.len != get_key_size(this))
	{
		return FALSE;
	}

	memcpy(this->state.nonce, key.ptr + key.len - sizeof(this->state.nonce),
		   sizeof(this->state.nonce));
	key.len -= sizeof(this->state.nonce);

	DESTROY_IF(this->key);
	this->key = aesni_key_create(TRUE, key);

	return this->key;
}

METHOD(crypter_t, destroy, void,
	private_aesni_ctr_t *this)
{
	DESTROY_IF(this->key);
	free(this);
}

/**
 * See header
 */
aesni_ctr_t *aesni_ctr_create(encryption_algorithm_t algo, size_t key_size)
{
	private_aesni_ctr_t *this;

	if (algo != ENCR_AES_CTR)
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

	INIT(this,
		.public = {
			.crypter = {
				.encrypt = _crypt,
				.decrypt = _crypt,
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
			this->crypt = encrypt_ctr128;
			break;
		case 24:
			this->crypt = encrypt_ctr192;
			break;
		case 32:
			this->crypt = encrypt_ctr256;
			break;
	}

	return &this->public;
}
