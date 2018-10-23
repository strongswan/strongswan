/*
 * Copyright (C) 2018 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2018 Atanas Filyanov
 * Rohde & Schwarz Cybersecurity GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "botan_aead.h"

#include <botan/build.h>

#if (defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)) || \
	defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)

#include <crypto/iv/iv_gen_seq.h>

#include <botan/ffi.h>

/**
 * As defined in RFC 4106 (GCM) and RFC 7634 (ChaPoly)
 */
#define IV_LEN			8
#define SALT_LEN		4
#define NONCE_LEN		(IV_LEN + SALT_LEN)
#define CHAPOLY_KEY_LEN	32

typedef struct private_aead_t private_aead_t;

struct private_aead_t {

	/**
	 * Public interface
	 */
	aead_t public;

	/**
	 * The encryption key
	 */
	chunk_t	key;

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
	 * The cipher to use
	 */
	const char* cipher_name;
};

/**
 * Do the actual en/decryption
 */
static bool do_crypt(private_aead_t *this, chunk_t data, chunk_t assoc,
					 chunk_t iv, u_char *out, uint32_t init_flag)
{
	botan_cipher_t cipher;
	uint8_t nonce[NONCE_LEN];
	size_t output_written = 0, input_consumed = 0;

	memcpy(nonce, this->salt, SALT_LEN);
	memcpy(nonce + SALT_LEN, iv.ptr, IV_LEN);

	if (botan_cipher_init(&cipher, this->cipher_name, init_flag))
	{
		return FALSE;
	}

	if (botan_cipher_set_key(cipher, this->key.ptr, this->key.len))
	{
		botan_cipher_destroy(cipher);
		return FALSE;
	}

	if (assoc.len &&
		botan_cipher_set_associated_data(cipher, assoc.ptr, assoc.len))
	{
		botan_cipher_destroy(cipher);
		return FALSE;
	}

	if (botan_cipher_start(cipher, nonce, NONCE_LEN))
	{
		botan_cipher_destroy(cipher);
		return FALSE;
	}

	if (init_flag == BOTAN_CIPHER_INIT_FLAG_ENCRYPT)
	{
		if (botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
								out, data.len + this->icv_size, &output_written,
								data.ptr, data.len, &input_consumed))
		{
			botan_cipher_destroy(cipher);
			return FALSE;
		}
	}
	else if (init_flag == BOTAN_CIPHER_INIT_FLAG_DECRYPT)
	{
		if (botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
								out, data.len, &output_written, data.ptr,
								data.len + this->icv_size, &input_consumed))
		{
			botan_cipher_destroy(cipher);
			return FALSE;
		}
	}

	botan_cipher_destroy(cipher);

	return TRUE;
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
	return do_crypt(this, plain, assoc, iv, out,
					BOTAN_CIPHER_INIT_FLAG_ENCRYPT);
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
	return do_crypt(this, encrypted, assoc, iv, out,
					BOTAN_CIPHER_INIT_FLAG_DECRYPT);
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
	return this->key.len + SALT_LEN;
}

METHOD(aead_t, set_key, bool,
	private_aead_t *this, chunk_t key)
{
	if (key.len != get_key_size(this))
	{
		return FALSE;
	}
	memcpy(this->salt, key.ptr + key.len - SALT_LEN, SALT_LEN);
	memcpy(this->key.ptr, key.ptr, this->key.len);
	return TRUE;
}

METHOD(aead_t, destroy, void,
	private_aead_t *this)
{
	chunk_clear(&this->key);
	this->iv_gen->destroy(this->iv_gen);
	free(this);
}

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)

/**
 * Determine the cipher name and ICV size for the given algorithm and key size
 */
static bool determine_gcm_params(private_aead_t *this,
								 encryption_algorithm_t algo, size_t key_size)
{
	switch (algo)
	{
		case ENCR_AES_GCM_ICV8:
			switch (key_size)
			{
				case 16:
					this->cipher_name = "AES-128/GCM(8)";
					break;
				case 24:
					this->cipher_name = "AES-192/GCM(8)";
					break;
				case 32:
					this->cipher_name = "AES-256/GCM(8)";
					break;
				default:
					return FALSE;
			}
			this->icv_size = 8;
			return TRUE;
		case ENCR_AES_GCM_ICV12:
			switch (key_size)
			{
				case 16:
					this->cipher_name = "AES-128/GCM(12)";
					break;
				case 24:
					this->cipher_name = "AES-192/GCM(12)";
					break;
				case 32:
					this->cipher_name = "AES-256/GCM(12)";
					break;
				default:
					return FALSE;
			}
			this->icv_size = 12;
			return TRUE;
		case ENCR_AES_GCM_ICV16:
			switch (key_size)
			{
				case 16:
					this->cipher_name = "AES-128/GCM";
					break;
				case 24:
					this->cipher_name = "AES-192/GCM";
					break;
				case 32:
					this->cipher_name = "AES-256/GCM";
					break;
				default:
					return FALSE;
			}
			this->icv_size = 16;
			return TRUE;
		default:
			return FALSE;
	}
}
#endif

/*
 * Described in header
 */
aead_t *botan_aead_create(encryption_algorithm_t algo, size_t key_size,
						  size_t salt_size)
{
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

	if (salt_size && salt_size != SALT_LEN)
	{
		free(this);
		return NULL;
	}

	switch (algo)
	{
#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
			if (!key_size)
			{
				key_size = 16;
			}
			if (!determine_gcm_params(this, algo, key_size))
			{
				free(this);
				return NULL;
			}
			break;
#endif
#ifdef BOTAN_HAS_AEAD_CHACHA20_POLY1305
		case ENCR_CHACHA20_POLY1305:
			if (key_size && key_size != CHAPOLY_KEY_LEN)
			{
				free(this);
				return NULL;
			}
			key_size = CHAPOLY_KEY_LEN;
			this->cipher_name = "ChaCha20Poly1305";
			this->icv_size = 16;
			break;
#endif
		default:
			free(this);
			return NULL;
	}

	this->key = chunk_alloc(key_size);
	this->iv_gen = iv_gen_seq_create();

	return &this->public;
}

#endif
