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
 * Generic CTR encryption
 */
static void encrypt_ctr(private_aesni_ctr_t *this,
						size_t len, u_char *in, u_char *out)
{
	__m128i state, t, d, b, swap, one, *bi, *bo;
	u_int i, round, blocks, rem;

	one = _mm_set_epi32(0, 0, 0, 1);
	swap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	state = _mm_load_si128((__m128i*)&this->state);
	blocks = len / AES_BLOCK_SIZE;
	rem = len % AES_BLOCK_SIZE;
	bi = (__m128i*)in;
	bo = (__m128i*)out;

	for (i = 0; i < blocks; i++)
	{
		d = _mm_loadu_si128(bi + i);
		t = _mm_xor_si128(state, this->key->schedule[0]);
		for (round = 1; round < this->key->rounds; round++)
		{
			t = _mm_aesenc_si128(t, this->key->schedule[round]);
		}
		t = _mm_aesenclast_si128(t, this->key->schedule[this->key->rounds]);
		t = _mm_xor_si128(t, d);
		_mm_storeu_si128(bo + i, t);

		/* big endian increment */
		t = _mm_shuffle_epi8(state, swap);
		t = _mm_add_epi64(t, one);
		state = _mm_shuffle_epi8(t, swap);
	}

	if (rem)
	{
		memset(&b, 0, sizeof(b));
		memcpy(&b, bi + blocks, rem);

		d = _mm_loadu_si128(&b);
		t = _mm_xor_si128(state, this->key->schedule[0]);
		for (round = 1; round < this->key->rounds; round++)
		{
			t = _mm_aesenc_si128(t, this->key->schedule[round]);
		}
		t = _mm_aesenclast_si128(t, this->key->schedule[this->key->rounds]);
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
		.crypt = encrypt_ctr,
	);

	return &this->public;
}
