/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General xcbc License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General xcbc License
 * for more details.
 *
 * $Id: xcbc.c 3589 2008-03-13 14:14:44Z martin $
 */

#include <string.h>

#include "xcbc.h"

#include <debug.h>

typedef struct private_xcbc_t private_xcbc_t;

/**
 * Private data of a xcbc_t object.
 * 
 * The variable names are the same as in the RFC.
 */
struct private_xcbc_t {
	/**
	 * Public xcbc_t interface.
	 */
	xcbc_t xcbc;
	
	/**
	 * Block size, in bytes
	 */
	u_int8_t b;
	
	/**
	 * crypter using k1
	 */
	crypter_t *k1;
	
	/**
	 * k2
	 */
	u_int8_t *k2;
	
	/**
	 * k3
	 */
	u_int8_t *k3;
};

/**
 * Implementation of xcbc_t.get_mac.
 */
static void get_mac(private_xcbc_t *this, chunk_t data, u_int8_t *e)
{
	int n, i, padding;
	u_int8_t *m;
	chunk_t iv;
	
	if (e == NULL)
	{
		DBG1("XCBC append mode not implemented!");
		/* TODO: append mode */
		return;
	}
	
	n = data.len / this->b;
	padding = data.len % this->b;
	if (padding || data.len == 0)
	{	/* do an additional block if we have padding or zero-length data */
		n++;
	}
	iv = chunk_alloca(this->b);
	memset(iv.ptr, 0, iv.len);
	m = data.ptr;
	
	/* (2) Define E[0] = 0x00000000000000000000000000000000 */
	memset(e, 0, this->b);
	
	/* (3) For each block M[i], where i = 1 ... n-1:
     *     XOR M[i] with E[i-1], then encrypt the result with Key K1,
     *     yielding E[i].
     */
	for (i = 1; i < n; i++)
	{
		memxor(e, m + (i - 1) * this->b, this->b);
		this->k1->encrypt(this->k1, chunk_create(e, this->b), iv, NULL);
	}
	
	/* (4) For block M[n]: */
	if (data.len && padding == 0)
	{
		/* a) If the blocksize of M[n] is 128 bits:
         *    XOR M[n] with E[n-1] and Key K2, then encrypt the result with
         *    Key K1, yielding E[n].
         */
		memxor(e, m + (i - 1) * this->b, this->b);
		memxor(e, this->k2, this->b);
		this->k1->encrypt(this->k1, chunk_create(e, this->b), iv, NULL);
	}
	else
	{
		/* b) If the blocksize of M[n] is less than 128 bits:
		 *
		 *  i) Pad M[n] with a single "1" bit, followed by the number of
         *     "0" bits (possibly none) required to increase M[n]'s
         *     blocksize to 128 bits.
         */
        u_int8_t *mn = alloca(this->b);
        memcpy(mn, m + (n - 1) * this->b, padding);
        mn[padding] = 0x80;
        while (++padding < this->b)
        {
	        mn[padding] = 0x00;
        }
        /*  ii) XOR M[n] with E[n-1] and Key K3, then encrypt the result
         *      with Key K1, yielding E[n].
         */
		memxor(e, mn, this->b);
		memxor(e, this->k3, this->b);
		this->k1->encrypt(this->k1, chunk_create(e, this->b), iv, NULL);
	}
}
	
/**
 * Implementation of xcbc_t.get_block_size.
 */
static size_t get_block_size(private_xcbc_t *this)
{
	return this->b;
}

/**
 * Implementation of xcbc_t.set_key.
 */
static void set_key(private_xcbc_t *this, chunk_t key)
{
	chunk_t iv, k1, lengthened;

	/* we support variable keys from RFC4434 */
	if (key.len == this->b)
	{
		lengthened = key;
	}
	else if (key.len < this->b)
	{	/* pad short keys */
		lengthened = chunk_alloca(this->b);
		memset(lengthened.ptr, 0, lengthened.len);
		memcpy(lengthened.ptr, key.ptr, key.len);
	}
	else
	{	/* shorten key using xcbc */
		lengthened = chunk_alloca(this->b);
		memset(lengthened.ptr, 0, lengthened.len);
		set_key(this, lengthened);
		get_mac(this, key, lengthened.ptr);
	}

	k1 = chunk_alloca(this->b);
	iv = chunk_alloca(this->b);
	memset(iv.ptr, 0, iv.len);
	
	/* 
	 * (1) Derive 3 128-bit keys (K1, K2 and K3) from the 128-bit secret
     *     key K, as follows:
     *     K1 = 0x01010101010101010101010101010101 encrypted with Key K
     *     K2 = 0x02020202020202020202020202020202 encrypted with Key K
     *     K3 = 0x03030303030303030303030303030303 encrypted with Key K
     */
	this->k1->set_key(this->k1, lengthened);
	memset(this->k2, 0x02, this->b);
	this->k1->encrypt(this->k1, chunk_create(this->k2, this->b), iv, NULL);
	memset(this->k3, 0x03, this->b);
	this->k1->encrypt(this->k1, chunk_create(this->k3, this->b), iv, NULL);
	memset(k1.ptr, 0x01, this->b);
	this->k1->encrypt(this->k1, k1, iv, NULL);
	this->k1->set_key(this->k1, k1);
}

/**
 * Implementation of xcbc_t.destroy.
 */
static void destroy(private_xcbc_t *this)
{
	this->k1->destroy(this->k1);
	free(this->k2);
	free(this->k3);
	free(this);
}

/*
 * Described in header
 */
xcbc_t *xcbc_create(encryption_algorithm_t algo, size_t key_size)
{
	private_xcbc_t *this;
	crypter_t *crypter;
	
	crypter = lib->crypto->create_crypter(lib->crypto, algo, key_size);
	if (!crypter)
	{
		return NULL;
	}
	/* input and output of crypter must be equal for xcbc */
	if (crypter->get_block_size(crypter) != key_size)
	{
		crypter->destroy(crypter);
		return NULL;
	}
	
	this = malloc_thing(private_xcbc_t);
	this->xcbc.get_mac = (void (*)(xcbc_t *,chunk_t,u_int8_t*))get_mac;
	this->xcbc.get_block_size = (size_t (*)(xcbc_t *))get_block_size;
	this->xcbc.set_key = (void (*)(xcbc_t *,chunk_t))set_key;
	this->xcbc.destroy = (void (*)(xcbc_t *))destroy;
	
	this->b = crypter->get_block_size(crypter);
	this->k1 = crypter;
	this->k2 = malloc(this->b);
	this->k3 = malloc(this->b);

	return &this->xcbc;
}

