/*
 * Copyright (C) 2008 Thomas Kallenberg
 * Copyright (C) 2008 Martin Willi
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

#include "padlock_aes_crypter.h"
#include <stdio.h>

#define AES_BLOCK_SIZE 16
#define PADLOCK_ALIGN __attribute__ ((__aligned__(16)))

typedef struct private_padlock_aes_crypter_t private_padlock_aes_crypter_t;

/**
 * Private data of padlock_aes_crypter_t
 */
struct private_padlock_aes_crypter_t {
	
	/**
	 * Public part of this class.
	 */
	padlock_aes_crypter_t public;
	
	/*
	 * the key
	 */
	chunk_t	key;
};

/**
 * Control word structure to pass to crypt operations
 */
typedef struct {
	u_int __attribute__ ((__packed__))
		rounds:4,
		algo:3,
		keygen:1,
		interm:1,
		encdec:1,
		ksize:2;
	/* microcode needs additional bytes for calculation */
	u_char buf[124];
} cword;

/**
 * Invoke the actual de/encryption
 */
static void padlock_crypt(void *key, void *ctrl, void *src, void *dst, 
						  int count, void *iv)
{
	asm volatile(
		"pushl %%eax\n pushl %%ebx\n pushl %%ecx\n"
		"pushl %%edx\n pushl %%esi\n pushl %%edi\n"
		"pushfl\n popfl\n"
		"movl %0, %%eax\n"
		"movl %1, %%ebx\n"
		"movl %2, %%ecx\n"
		"movl %3, %%edx\n"
		"movl %4, %%esi\n"
		"movl %5, %%edi\n"
		"rep\n"
		".byte 0x0f, 0xa7, 0xd0\n"
		"popl %%edi\n popl %%esi\n popl %%edx\n"
		"popl %%ecx\n popl %%ebx\n popl %%eax\n"
		:
		: "m"(iv),"m"(key), "m"(count), "m"(ctrl), "m"(src), "m"(dst)
		: "eax", "ecx", "edx", "esi", "edi");
}

/*
 * Implementation of crypter_t.crypt
 */
static void crypt(private_padlock_aes_crypter_t *this, char *iv, 
				  chunk_t src, chunk_t *dst, bool enc)
{
	cword cword PADLOCK_ALIGN;
	u_char key_aligned[256] PADLOCK_ALIGN;
	u_char iv_aligned[16] PADLOCK_ALIGN;

	memset(&cword, 0, sizeof(cword));

	/* set encryption/decryption flag */
	cword.encdec = enc;
	/* calculate rounds and key size */
	cword.rounds = 10 + (this->key.len - 16) / 4;
	cword.ksize = (this->key.len - 16) / 8;
	/* enable autoalign */
	cword.algo |= 2;

	/* move data to aligned buffers */
	memcpy(iv_aligned, iv, sizeof(iv_aligned));
	memcpy(key_aligned, this->key.ptr, this->key.len);

	*dst = chunk_alloc(src.len);
	padlock_crypt(key_aligned, &cword, src.ptr, dst->ptr,
				  src.len / AES_BLOCK_SIZE, iv_aligned);
}

/**
 * Implementation of crypter_t.decrypt.
 */
static void decrypt(private_padlock_aes_crypter_t *this, chunk_t data, 
						chunk_t iv, chunk_t *dst)
{
	crypt(this, iv.ptr, data, dst, TRUE);
}


/**
 * Implementation of crypter_t.encrypt.
 */
static void encrypt (private_padlock_aes_crypter_t *this, chunk_t data, 
							chunk_t iv, chunk_t *dst)
{
	crypt(this, iv.ptr, data, dst, FALSE);
}

/**
 * Implementation of crypter_t.get_block_size.
 */
static size_t get_block_size(private_padlock_aes_crypter_t *this)
{
	return AES_BLOCK_SIZE;
}

/**
 * Implementation of crypter_t.get_key_size.
 */
static size_t get_key_size(private_padlock_aes_crypter_t *this)
{
	return this->key.len;
}

/**
 * Implementation of crypter_t.set_key.
 */
static void set_key(private_padlock_aes_crypter_t *this, chunk_t key)
{
	memcpy(this->key.ptr, key.ptr, min(key.len, this->key.len));
}

/**
 * Implementation of crypter_t.destroy and aes_crypter_t.destroy.
 */
static void destroy (private_padlock_aes_crypter_t *this)
{
	free(this->key.ptr);
	free(this);
}

/*
 * Described in header
 */
padlock_aes_crypter_t *padlock_aes_crypter_create(encryption_algorithm_t algo, 
												  size_t key_size)
{
	private_padlock_aes_crypter_t *this;
	
	if (algo != ENCR_AES_CBC)
	{
		return NULL;
	}
	
	this = malloc_thing(private_padlock_aes_crypter_t);
	
	switch (key_size)
	{
		case 16:        /* AES 128 */
			break;
		case 24:        /* AES-192 */
		case 32:        /* AES-256 */
			/* These need an expanded key, currently not supported, FALL */
		default:
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
