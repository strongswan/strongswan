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
 * Generic CBC encryption
 */
static void encrypt_cbc(aesni_key_t *key, u_int blocks, u_char *in,
						u_char *iv, u_char *out)
{
	__m128i t, fb, *bi, *bo;
	int i, round;

	bi = (__m128i*)in;
	bo = (__m128i*)out;

	fb = _mm_loadu_si128((__m128i*)iv);
	for (i = 0; i < blocks; i++)
	{
		t = _mm_loadu_si128(bi + i);
		fb = _mm_xor_si128(t, fb);
		fb = _mm_xor_si128(fb, key->schedule[0]);
		for (round = 1; round < key->rounds; round++)
		{
			fb = _mm_aesenc_si128(fb, key->schedule[round]);
		}
		fb = _mm_aesenclast_si128(fb, key->schedule[key->rounds]);
		_mm_storeu_si128(bo + i, fb);
	}
}

/**
 * Generic CBC decryption
 */
static void decrypt_cbc(aesni_key_t *key, u_int blocks, u_char *in,
						u_char *iv, u_char *out)
{
	__m128i t, fb, last, *bi, *bo;
	int i, round;

	bi = (__m128i*)in;
	bo = (__m128i*)out;

	fb = _mm_loadu_si128((__m128i*)iv);
	for (i = 0; i < blocks; i++)
	{
		last = _mm_loadu_si128(bi + i);
		t = _mm_xor_si128(last, key->schedule[0]);
		for (round = 1; round  < key->rounds; round++)
		{
			t = _mm_aesdec_si128(t, key->schedule[round]);
		}
		t = _mm_aesdeclast_si128(t, key->schedule[key->rounds]);
		t = _mm_xor_si128(t, fb);
		_mm_storeu_si128(bo + i, t);
		fb = last;
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
	free(this);
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

	INIT(this,
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
		.encrypt = encrypt_cbc,
		.decrypt = decrypt_cbc,
	);

	return &this->public;
}
