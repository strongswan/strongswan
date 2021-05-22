/*
 * Copyright (C) 2008 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "gmalg_crypter.h"

#include <gmalg.h>

typedef struct private_gmalg_crypter_t private_gmalg_crypter_t;

/**
 * Private data of gmalg_crypter_t
 */
struct private_gmalg_crypter_t {

	/**
	 * Public part of this class.
	 */
	gmalg_crypter_t public;

	/*
	 * the key
	 */
	chunk_t	key;

	/*
	 * the cipher to use
	 */
	encryption_algorithm_t algo;

	/*
	 * the cipher ddevice handle
	 */
	void *hDeviceHandle;
};

/**
 * Do the actual en/decryption in an EVP context
 */
static bool crypt(private_gmalg_crypter_t *this, chunk_t data, chunk_t iv,
				  chunk_t *dst, int enc)
{
	bool success = TRUE;
	u_int alg_mode;
	u_char *out;
	u_int len;
	int rc;

	switch (this->algo)
	{
		case ENCR_SM1_ECB:
			alg_mode = GMALG_SM1_ECB;
			break;
		case ENCR_SM1_CBC:
			alg_mode = GMALG_SM1_CBC;
			break;
		case ENCR_SM4_ECB:
			alg_mode = GMALG_SM4_CBC;
			break;
		case ENCR_SM4_CBC:
			alg_mode = GMALG_SM4_CBC;
			break;
		default:
		{
			/* algo unavailable invalid */
			return FALSE;
		}
	}

	out = data.ptr;
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		out = dst->ptr;
	}

	if (enc)
		rc = GMALG_Encrypt(this->hDeviceHandle, this->key.ptr, alg_mode, iv.ptr, data.ptr, data.len, out, &len);
	else
		rc = GMALG_Decrypt(this->hDeviceHandle, this->key.ptr, alg_mode, iv.ptr, data.ptr, data.len, out, &len);
	if(rc)
		success = FALSE;

	return success;
}

METHOD(crypter_t, decrypt, bool,
	private_gmalg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 0);
}

METHOD(crypter_t, encrypt, bool,
	private_gmalg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 1);
}

METHOD(crypter_t, get_block_size, size_t,
	private_gmalg_crypter_t *this)
{
	return 16;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_gmalg_crypter_t *this)
{
	return 16;
}

METHOD(crypter_t, get_key_size, size_t,
	private_gmalg_crypter_t *this)
{
	return this->key.len;
}

METHOD(crypter_t, set_key, bool,
	private_gmalg_crypter_t *this, chunk_t key)
{
	memcpy(this->key.ptr, key.ptr, min(key.len, this->key.len));
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_gmalg_crypter_t *this)
{
	GMALG_CloseDevice(this->hDeviceHandle);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
gmalg_crypter_t *gmalg_crypter_create(encryption_algorithm_t algo,
												  size_t key_size)
{
	private_gmalg_crypter_t *this;

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
	);

	this->algo = algo;
	this->key = chunk_alloc(key_size);
	GMALG_OpenDevice(&this->hDeviceHandle);

	return &this->public;
}
