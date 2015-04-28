/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL

#include "openssl_gcm.h"

#include <openssl/evp.h>
#include <crypto/iv/iv_gen_seq.h>

/** as defined in RFC 4106 */
#define IV_LEN		8
#define SALT_LEN	4
#define NONCE_LEN	(IV_LEN + SALT_LEN)

typedef struct private_aead_t private_aead_t;

/**
 * Private data of aead_t
 */
struct private_aead_t {

	/**
	 * Public interface
	 */
	aead_t public;

	/**
	 * The key size
	 */
	size_t key_size;

	/**
	 * Salt value
	 */
	char salt[SALT_LEN];

	/**
	 * Size of the integrity check value
	 */
	size_t icv_size;

	/**
	 * IV generator
	 */
	iv_gen_t *iv_gen;

	/**
	 * Context with key schedule
	 */
	EVP_CIPHER_CTX ctx;
};

/**
 * Do the actual en/decryption in an EVP context
 */
static bool crypt(private_aead_t *this, chunk_t data, chunk_t assoc, chunk_t iv,
				  u_char *out, int enc)
{
	u_char nonce[NONCE_LEN];
	bool success = FALSE;
	int len;

	memcpy(nonce, this->salt, SALT_LEN);
	memcpy(nonce + SALT_LEN, iv.ptr, IV_LEN);

	if (!EVP_CipherInit_ex(&this->ctx, NULL, NULL, NULL, nonce, enc))
	{
		goto done;
	}
	if (!enc && !EVP_CIPHER_CTX_ctrl(&this->ctx, EVP_CTRL_GCM_SET_TAG,
									 this->icv_size, data.ptr + data.len))
	{	/* set ICV for verification on decryption */
		goto done;
	}
	if (assoc.len && !EVP_CipherUpdate(&this->ctx, NULL, &len,
									   assoc.ptr, assoc.len))
	{	/* set AAD if specified */
		goto done;
	}
	if (!EVP_CipherUpdate(&this->ctx, out, &len, data.ptr, data.len) ||
		!EVP_CipherFinal_ex(&this->ctx, out + len, &len))
	{	/* EVP_CipherFinal_ex fails if ICV is incorrect on decryption */
		goto done;
	}
	if (enc && !EVP_CIPHER_CTX_ctrl(&this->ctx, EVP_CTRL_GCM_GET_TAG,
									this->icv_size, out + data.len))
	{	/* copy back the ICV when encrypting */
		goto done;
	}
	success = TRUE;

done:
	return success;
}

METHOD(aead_t, encrypt, bool,
	private_aead_t *this, chunk_t plain, chunk_t assoc, chunk_t iv,
	chunk_t *encrypted)
{
	u_char *out;

	out = plain.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(plain.len + this->icv_size);
		out = encrypted->ptr;
	}
	return crypt(this, plain, assoc, iv, out, 1);
}

METHOD(aead_t, decrypt, bool,
	private_aead_t *this, chunk_t encrypted, chunk_t assoc, chunk_t iv,
	chunk_t *plain)
{
	u_char *out;

	if (encrypted.len < this->icv_size)
	{
		return FALSE;
	}
	encrypted.len -= this->icv_size;

	out = encrypted.ptr;
	if (plain)
	{
		*plain = chunk_alloc(encrypted.len);
		out = plain->ptr;
	}
	return crypt(this, encrypted, assoc, iv, out, 0);
}

METHOD(aead_t, get_block_size, size_t,
	private_aead_t *this)
{
	return 1;
}

METHOD(aead_t, get_icv_size, size_t,
	private_aead_t *this)
{
	return this->icv_size;
}

METHOD(aead_t, get_iv_size, size_t,
	private_aead_t *this)
{
	return IV_LEN;
}

METHOD(aead_t, get_iv_gen, iv_gen_t*,
	private_aead_t *this)
{
	return this->iv_gen;
}

METHOD(aead_t, get_key_size, size_t,
	private_aead_t *this)
{
	return this->key_size + SALT_LEN;
}

METHOD(aead_t, set_key, bool,
	private_aead_t *this, chunk_t key)
{
	if (key.len != get_key_size(this))
	{
		return FALSE;
	}
	memcpy(this->salt, key.ptr + key.len - SALT_LEN, SALT_LEN);

	if (!EVP_CipherInit_ex(&this->ctx, NULL, NULL, key.ptr, NULL, 0))
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(aead_t, destroy, void,
	private_aead_t *this)
{
	EVP_CIPHER_CTX_cleanup(&this->ctx);
	this->iv_gen->destroy(this->iv_gen);
	free(this);
}

/*
 * Described in header
 */
aead_t *openssl_gcm_create(encryption_algorithm_t algo,
						   size_t key_size, size_t salt_size)
{
	const EVP_CIPHER *cipher = NULL;
	private_aead_t *this;

	INIT(this,
		.public = {
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
	);

	switch (algo)
	{
		case ENCR_AES_GCM_ICV8:
			this->icv_size = 8;
			break;
		case ENCR_AES_GCM_ICV12:
			this->icv_size = 12;
			break;
		case ENCR_AES_GCM_ICV16:
			this->icv_size = 16;
			break;
		default:
			free(this);
			return NULL;
	}

	if (salt_size && salt_size != SALT_LEN)
	{
		/* currently not supported */
		free(this);
		return NULL;
	}

	switch (algo)
	{
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
			switch (key_size)
			{
				case 0:
					key_size = 16;
					/* FALL */
				case 16:
					cipher = EVP_get_cipherbyname("aes-128-gcm");
					break;
				case 24:
					cipher = EVP_get_cipherbyname("aes-192-gcm");
					break;
				case 32:
					cipher = EVP_get_cipherbyname("aes-256-gcm");
					break;
				default:
					free(this);
					return NULL;
			}
			break;
		default:
			free(this);
			return NULL;
	}

	if (!cipher)
	{
		free(this);
		return NULL;
	}

	this->key_size = key_size;
	this->iv_gen = iv_gen_seq_create();

	EVP_CIPHER_CTX_init(&this->ctx);
	EVP_CIPHER_CTX_set_padding(&this->ctx, 0);

	if (!EVP_CipherInit_ex(&this->ctx, cipher, NULL, NULL, NULL, 0))
	{
		destroy(this);
		return NULL;
	}
	if (!EVP_CIPHER_CTX_ctrl(&this->ctx, EVP_CTRL_GCM_SET_IVLEN,
							 NONCE_LEN, NULL))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

#endif /* OPENSSL_VERSION_NUMBER */
