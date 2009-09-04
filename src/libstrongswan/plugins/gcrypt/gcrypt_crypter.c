/*
 * Copyright (C) 2009 Martin Willi
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

#include "gcrypt_crypter.h"

#include <gcrypt.h>

#include <debug.h>

typedef struct private_gcrypt_crypter_t private_gcrypt_crypter_t;

/**
 * Private data of gcrypt_crypter_t
 */
struct private_gcrypt_crypter_t {

	/**
	 * Public part of this class.
	 */
	gcrypt_crypter_t public;

	/**
	 * gcrypt cipher handle
	 */
	gcry_cipher_hd_t h;

	/**
	 * gcrypt algorithm identifier
	 */
	int alg;
};

/**
 * Implementation of crypter_t.decrypt.
 */
static void decrypt(private_gcrypt_crypter_t *this, chunk_t data,
					chunk_t iv, chunk_t *dst)
{
	gcry_cipher_setiv(this->h, iv.ptr, iv.len);

	if (dst)
	{
		*dst = chunk_alloc(data.len);
		gcry_cipher_decrypt(this->h, dst->ptr, dst->len, data.ptr, data.len);
	}
	else
	{
		gcry_cipher_decrypt(this->h, data.ptr, data.len, NULL, 0);
	}
}

/**
 * Implementation of crypter_t.encrypt.
 */
static void encrypt(private_gcrypt_crypter_t *this, chunk_t data,
					chunk_t iv, chunk_t *dst)
{
	gcry_cipher_setiv(this->h, iv.ptr, iv.len);

	if (dst)
	{
		*dst = chunk_alloc(data.len);
		gcry_cipher_encrypt(this->h, dst->ptr, dst->len, data.ptr, data.len);
	}
	else
	{
		gcry_cipher_encrypt(this->h, data.ptr, data.len, NULL, 0);
	}
}

/**
 * Implementation of crypter_t.get_block_size.
 */
static size_t get_block_size(private_gcrypt_crypter_t *this)
{
	size_t len = 0;

	gcry_cipher_algo_info(this->alg, GCRYCTL_GET_BLKLEN, NULL, &len);
	return len;
}

/**
 * Implementation of crypter_t.get_key_size.
 */
static size_t get_key_size(private_gcrypt_crypter_t *this)
{
	size_t len = 0;

	gcry_cipher_algo_info(this->alg, GCRYCTL_GET_KEYLEN, NULL, &len);
	return len;
}

/**
 * Implementation of crypter_t.set_key.
 */
static void set_key(private_gcrypt_crypter_t *this, chunk_t key)
{
	gcry_cipher_setkey(this->h, key.ptr, key.len);
}

/**
 * Implementation of crypter_t.destroy.
 */
static void destroy (private_gcrypt_crypter_t *this)
{
	gcry_cipher_close(this->h);
	free(this);
}

/*
 * Described in header
 */
gcrypt_crypter_t *gcrypt_crypter_create(encryption_algorithm_t algo,
										size_t key_size)
{
	private_gcrypt_crypter_t *this;
	int gcrypt_alg;
	int mode = GCRY_CIPHER_MODE_CBC;
	gcry_error_t err;

	switch (algo)
	{
		case ENCR_DES:
			gcrypt_alg = GCRY_CIPHER_DES;
			break;
		case ENCR_DES_ECB:
			gcrypt_alg = GCRY_CIPHER_DES;
			mode = GCRY_CIPHER_MODE_ECB;
			break;
		case ENCR_3DES:
			gcrypt_alg = GCRY_CIPHER_3DES;
			break;
		case ENCR_IDEA:
			/* currently not implemented in gcrypt */
			return NULL;
		case ENCR_CAST:
			gcrypt_alg = GCRY_CIPHER_CAST5;
			break;
		case ENCR_BLOWFISH:
			if (key_size != 16)
			{	/* gcrypt currently supports 128 bit blowfish only */
				return NULL;
			}
			gcrypt_alg = GCRY_CIPHER_BLOWFISH;
			break;
		/* case ENCR_AES_CTR:
			mode = GCRY_CIPHER_MODE_CTR; */
			/* fall */
		case ENCR_AES_CBC:
			switch (key_size)
			{
				case 16:
					gcrypt_alg = GCRY_CIPHER_AES128;
					break;
				case 24:
					gcrypt_alg = GCRY_CIPHER_AES192;
					break;
				case 32:
					gcrypt_alg = GCRY_CIPHER_AES256;
					break;
				default:
					return NULL;
			}
			break;
		/* case ENCR_CAMELLIA_CTR:
			mode = GCRY_CIPHER_MODE_CTR; */
			/* fall */
		case ENCR_CAMELLIA_CBC:
			switch (key_size)
			{
#ifdef HAVE_GCRY_CIPHER_CAMELLIA
				case 16:
					gcrypt_alg = GCRY_CIPHER_CAMELLIA128;
					break;
				case 24:
					gcrypt_alg = GCRY_CIPHER_CAMELLIA192;
					break;
				case 32:
					gcrypt_alg = GCRY_CIPHER_CAMELLIA256;
					break;
#endif /* HAVE_GCRY_CIPHER_CAMELLIA */
				default:
					return NULL;
			}
			break;
		case ENCR_SERPENT_CBC:
			switch (key_size)
			{
				case 16:
					gcrypt_alg = GCRY_CIPHER_SERPENT128;
					break;
				case 24:
					gcrypt_alg = GCRY_CIPHER_SERPENT192;
					break;
				case 32:
					gcrypt_alg = GCRY_CIPHER_SERPENT256;
					break;
				default:
					return NULL;
			}
			break;
		case ENCR_TWOFISH_CBC:
			switch (key_size)
			{
				case 16:
					gcrypt_alg = GCRY_CIPHER_TWOFISH128;
					break;
				case 32:
					gcrypt_alg = GCRY_CIPHER_TWOFISH;
					break;
				default:
					return NULL;
			}
			break;
		default:
			return NULL;
	}

	this = malloc_thing(private_gcrypt_crypter_t);

	this->alg = gcrypt_alg;
	err = gcry_cipher_open(&this->h, gcrypt_alg, mode, 0);
	if (err)
	{
		DBG1("grcy_cipher_open(%N) failed: %s",
			 encryption_algorithm_names, algo, gpg_strerror(err));
		free(this);
		return NULL;
	}

	this->public.crypter_interface.encrypt = (void (*) (crypter_t *, chunk_t,chunk_t, chunk_t *))encrypt;
	this->public.crypter_interface.decrypt = (void (*) (crypter_t *, chunk_t , chunk_t, chunk_t *))decrypt;
	this->public.crypter_interface.get_block_size = (size_t (*) (crypter_t *))get_block_size;
	this->public.crypter_interface.get_key_size = (size_t (*) (crypter_t *))get_key_size;
	this->public.crypter_interface.set_key = (void (*) (crypter_t *,chunk_t))set_key;
	this->public.crypter_interface.destroy = (void (*) (crypter_t *))destroy;

	return &this->public;
}

