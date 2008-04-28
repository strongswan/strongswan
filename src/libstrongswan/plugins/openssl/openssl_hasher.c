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

#include "openssl_hasher.h"

#include <openssl/evp.h>

typedef struct private_openssl_hasher_t private_openssl_hasher_t;

/**
 * Private data of openssl_hasher_t
 */
struct private_openssl_hasher_t {
	
	/**
	 * Public part of this class.
	 */
	openssl_hasher_t public;
	
	/**
	 * data collected to hash
	 */
	chunk_t data;
	
	/*
	 * the hasher to use
	 */
	const EVP_MD *hasher;
};

/**
 * Mapping from the algorithms defined in IKEv2 to
 * OpenSSL algorithm names
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
} openssl_algorithm_t;

#define END_OF_LIST -1

/**
 * Algorithms for integrity
 */
static openssl_algorithm_t integrity_algs[] = {
	{HASH_MD2,		"md2"},
	{HASH_MD5,		"md5"},
	{HASH_SHA1,		"sha1"},
	{HASH_SHA256,	"sha256"},
	{HASH_SHA384,	"sha384"},
	{HASH_SHA512, 	"sha512"},
	{END_OF_LIST, 	NULL},
};

/**
 * Look up an OpenSSL algorithm name
 */
static char* lookup_algorithm(openssl_algorithm_t *openssl_algo, 
					   u_int16_t ikev2_algo)
{
	while (openssl_algo->ikev2_id != END_OF_LIST)
	{
		if (ikev2_algo == openssl_algo->ikev2_id)
		{
			return openssl_algo->name;
		}
		openssl_algo++;
	}
	return NULL;
}

/**
 * append data to the to-be-hashed buffer
 */
static void append_data(private_openssl_hasher_t *this, chunk_t data)
{
	this->data.ptr = realloc(this->data.ptr, this->data.len + data.len);
	memcpy(this->data.ptr + this->data.len, data.ptr, data.len);
	this->data.len += data.len;
}

/**
 * hash a buffer of data
 */
static void hash_data(private_openssl_hasher_t *this, chunk_t data, u_int8_t *digest)
{
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, this->hasher, NULL);
	EVP_DigestUpdate(&ctx, data.ptr, data.len);
	EVP_DigestFinal_ex(&ctx, digest, NULL);
	EVP_MD_CTX_cleanup(&ctx);
}

/**
 * Implementation of hasher_t.get_hash_size.
 */
static size_t get_hash_size(private_openssl_hasher_t *this)
{
	return this->hasher->md_size;
}

/**
 * Implementation of hasher_t.reset.
 */
static void reset(private_openssl_hasher_t *this)
{
	chunk_free(&this->data);
}

/**
 * Implementation of hasher_t.get_hash.
 */
static void get_hash(private_openssl_hasher_t *this, chunk_t chunk,
					 u_int8_t *hash)
{
	if (hash)
	{
		if (this->data.len)
		{
			append_data(this, chunk);
			hash_data(this, this->data, hash);
		}
		else
		{   /* hash directly if no previous data found */   
			hash_data(this, chunk, hash);
		}
		reset(this);
	}
	else
	{
		append_data(this, chunk);	
	}
}

/**
 * Implementation of hasher_t.allocate_hash.
 */
static void allocate_hash(private_openssl_hasher_t *this, chunk_t chunk,
						  chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(get_hash_size(this));
		get_hash(this, chunk, hash->ptr);
	}
	else
	{
		get_hash(this, chunk, NULL);	
	}
}

/**
 * Implementation of hasher_t.destroy.
 */
static void destroy (private_openssl_hasher_t *this)
{
	free(this->data.ptr);
	free(this);
}

/*
 * Described in header
 */
openssl_hasher_t *openssl_hasher_create(hash_algorithm_t algo)
{
	private_openssl_hasher_t *this;
	
	char* name = lookup_algorithm(integrity_algs, algo);
	if (!name)
	{
		/* algo unavailable */
		return NULL;
	}

	this = malloc_thing(private_openssl_hasher_t);
	
	this->hasher = EVP_get_digestbyname(name);
	if (!this->hasher)
	{
		/* OpenSSL does not support the requested algo */
		free(this);
		return NULL;
	}
	
	this->public.hasher_interface.get_hash = (void (*) (hasher_t*, chunk_t, u_int8_t*))get_hash;
	this->public.hasher_interface.allocate_hash = (void (*) (hasher_t*, chunk_t, chunk_t*))allocate_hash;
	this->public.hasher_interface.get_hash_size = (size_t (*) (hasher_t*))get_hash_size;
	this->public.hasher_interface.reset = (void (*) (hasher_t*))reset;
	this->public.hasher_interface.destroy = (void (*) (hasher_t*))destroy;
	
	this->data = chunk_empty;
	
	return &this->public;
}
