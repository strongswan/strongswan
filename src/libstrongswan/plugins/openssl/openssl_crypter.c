/*
 * Copyright (C) 2008 Tobias Brunner
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
 *
 * $Id$
 */

#include "openssl_crypter.h"

#include <openssl/evp.h>

typedef struct private_openssl_crypter_t private_openssl_crypter_t;

/**
 * Private data of openssl_crypter_t
 */
struct private_openssl_crypter_t {
	
	/**
	 * Public part of this class.
	 */
	openssl_crypter_t public;
	
	/*
	 * the key
	 */
	chunk_t	key;
	
	/*
	 * the cipher to use
	 */
	const EVP_CIPHER *cipher;
};

/**
 * Mapping from the algorithms defined in IKEv2 to
 * OpenSSL algorithm names and their key length
 */
typedef struct {
	/**
	 * Identifier specified in IKEv2
	 */
	int ikev2_id;
	
	/**
	 * Name of the algorithm, as used in OpenSSL
	 */
	char *name;
	
	/**
	 * Minimum valid key length in bytes
	 */
	size_t key_size_min;
	
	/**
	 * Maximum valid key length in bytes
	 */
	size_t key_size_max;
} openssl_algorithm_t;

#define END_OF_LIST -1

/**
 * Algorithms for encryption
 */
static openssl_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64, 	"***", 			0,	0}, */
	{ENCR_DES, 			"des",			8,	8},		/* 64 bits */
	{ENCR_3DES, 		"des3",			24,	24},	/* 192 bits */
	{ENCR_RC5, 			"rc5", 			5,	255},	/* 40 to 2040 bits, RFC 2451 */
	{ENCR_IDEA, 		"idea",			16,	16},	/* 128 bits, RFC 2451 */
	{ENCR_CAST, 		"cast",			5,	16},	/* 40 to 128 bits, RFC 2451 */
	{ENCR_BLOWFISH, 	"blowfish",		5,	56},	/* 40 to 448 bits, RFC 2451 */
/*	{ENCR_3IDEA, 		"***",			0,	0}, */
/*	{ENCR_DES_IV32, 	"***",			0,	0}, */
/*	{ENCR_NULL, 		"***",			0,	0}, */ /* handled separately */
/*	{ENCR_AES_CBC, 		"***",			0,	0}, */ /* handled separately */
/*	{ENCR_AES_CTR, 		"***",			0,	0}, */ /* disabled in evp.h */
	{END_OF_LIST, 		NULL,			0,	0},
};

/**
 * Look up an OpenSSL algorithm name and validate its key size
 */
static char* lookup_algorithm(openssl_algorithm_t *openssl_algo, 
					   u_int16_t ikev2_algo, size_t key_size)
{
	while (openssl_algo->ikev2_id != END_OF_LIST)
	{
		if (ikev2_algo == openssl_algo->ikev2_id)
		{
			/* validate key size */
			if (key_size < openssl_algo->key_size_min ||
				key_size > openssl_algo->key_size_max)
			{
				return NULL;
			}
			return openssl_algo->name;
		}
		openssl_algo++;
	}
	return NULL;
}

static void crypt(private_openssl_crypter_t *this, chunk_t data,
					chunk_t iv, chunk_t *dst, int enc)
{
	int len;
	u_char *out;
	
	out = data.ptr;
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		out = dst->ptr;
	}
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, this->cipher, NULL, this->key.ptr, iv.ptr, enc);
	EVP_CIPHER_CTX_set_padding(&ctx, 0); /* disable padding */
	EVP_CipherUpdate(&ctx, out, &len, data.ptr, data.len);
	EVP_CipherFinal_ex(&ctx, out, &len); /* since padding is disabled this does nothing */
	EVP_CIPHER_CTX_cleanup(&ctx);
}

/**
 * Implementation of crypter_t.decrypt.
 */
static void decrypt(private_openssl_crypter_t *this, chunk_t data, 
						chunk_t iv, chunk_t *dst)
{
	crypt(this, data, iv, dst, 0);
}


/**
 * Implementation of crypter_t.encrypt.
 */
static void encrypt (private_openssl_crypter_t *this, chunk_t data, 
							chunk_t iv, chunk_t *dst)
{
	crypt(this, data, iv, dst, 1);
}

/**
 * Implementation of crypter_t.get_block_size.
 */
static size_t get_block_size(private_openssl_crypter_t *this)
{
	return this->cipher->block_size;
}

/**
 * Implementation of crypter_t.get_key_size.
 */
static size_t get_key_size(private_openssl_crypter_t *this)
{
	return this->key.len;
}

/**
 * Implementation of crypter_t.set_key.
 */
static void set_key(private_openssl_crypter_t *this, chunk_t key)
{
	memcpy(this->key.ptr, key.ptr, min(key.len, this->key.len));
}

/**
 * Implementation of crypter_t.destroy.
 */
static void destroy (private_openssl_crypter_t *this)
{
	free(this->key.ptr);
	free(this);
}

/*
 * Described in header
 */
openssl_crypter_t *openssl_crypter_create(encryption_algorithm_t algo, 
												  size_t key_size)
{
	private_openssl_crypter_t *this;
	
	this = malloc_thing(private_openssl_crypter_t);
	
	switch (algo)
	{
		case ENCR_NULL:
			this->cipher = EVP_enc_null();
			break;
		case ENCR_AES_CBC:
			switch (key_size)
			{
				case 16:        /* AES 128 */
					this->cipher = EVP_get_cipherbyname("aes128");
					break;
				case 24:        /* AES-192 */
					this->cipher = EVP_get_cipherbyname("aes192");
					break;
				case 32:        /* AES-256 */
					this->cipher = EVP_get_cipherbyname("aes256"); 
					break;
				default:
					free(this);
					return NULL;
			}
			break;
		default:
		{
			char* name = lookup_algorithm(encryption_algs, algo, key_size);
			if (!name)
			{
				/* algo unavailable or key_size invalid */
				free(this);
				return NULL;
			}
			this->cipher = EVP_get_cipherbyname(name);
			break;
		}
	}
	
	if (!this->cipher)
	{
		/* OpenSSL does not support the requested algo */
		free(this);
		return NULL;
	}
	
	this->key = chunk_alloc(key_size);
	
	this->public.crypter_interface.encrypt = (void (*) (crypter_t *, chunk_t,chunk_t, chunk_t *)) encrypt;
	this->public.crypter_interface.decrypt = (void (*) (crypter_t *, chunk_t , chunk_t, chunk_t *)) decrypt;
	this->public.crypter_interface.get_block_size = (size_t (*) (crypter_t *)) get_block_size;
	this->public.crypter_interface.get_key_size = (size_t (*) (crypter_t *)) get_key_size;
	this->public.crypter_interface.set_key = (void (*) (crypter_t *,chunk_t)) set_key;
	this->public.crypter_interface.destroy = (void (*) (crypter_t *)) destroy;
	
	return &this->public;
}
