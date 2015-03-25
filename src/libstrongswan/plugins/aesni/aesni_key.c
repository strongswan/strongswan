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
		default:
			break;
	}

	if (!encrypt)
	{
		reverse_key(&this->public);
	}

	return &this->public;
}
