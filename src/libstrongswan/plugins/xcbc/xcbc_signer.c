/*
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
 */

#include <string.h>

#include "xcbc_signer.h"
#include "xcbc.h"

typedef struct private_xcbc_signer_t private_xcbc_signer_t;

/**
 * Private data structure with signing context.
 */
struct private_xcbc_signer_t {

	/**
	 * Public interface of xcbc_signer_t.
	 */
	xcbc_signer_t public;

	/**
	 * Assigned xcbc function.
	 */
	xcbc_t *xcbc;

	/**
	 * Block size (truncation of XCBC MAC)
	 */
	size_t block_size;
};

/**
 * Implementation of signer_t.get_signature.
 */
static void get_signature(private_xcbc_signer_t *this,
						  chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{	/* append mode */
		this->xcbc->get_mac(this->xcbc, data, NULL);
	}
	else
	{
		u_int8_t mac[this->xcbc->get_block_size(this->xcbc)];

		this->xcbc->get_mac(this->xcbc, data, mac);
		memcpy(buffer, mac, this->block_size);
	}
}

/**
 * Implementation of signer_t.allocate_signature.
 */
static void allocate_signature (private_xcbc_signer_t *this,
								chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{	/* append mode */
		this->xcbc->get_mac(this->xcbc, data, NULL);
	}
	else
	{
		u_int8_t mac[this->xcbc->get_block_size(this->xcbc)];

		this->xcbc->get_mac(this->xcbc, data, mac);

		chunk->ptr = malloc(this->block_size);
		chunk->len = this->block_size;

		memcpy(chunk->ptr, mac, this->block_size);
	}
}

/**
 * Implementation of signer_t.verify_signature.
 */
static bool verify_signature(private_xcbc_signer_t *this,
							 chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->xcbc->get_block_size(this->xcbc)];

	if (signature.len != this->block_size)
	{
		return FALSE;
	}

	this->xcbc->get_mac(this->xcbc, data, mac);
	return memeq(signature.ptr, mac, this->block_size);
}

/**
 * Implementation of signer_t.get_key_size.
 */
static size_t get_key_size(private_xcbc_signer_t *this)
{
	return this->xcbc->get_block_size(this->xcbc);
}

/**
 * Implementation of signer_t.get_block_size.
 */
static size_t get_block_size(private_xcbc_signer_t *this)
{
	return this->block_size;
}

/**
 * Implementation of signer_t.set_key.
 */
static void set_key(private_xcbc_signer_t *this, chunk_t key)
{
	this->xcbc->set_key(this->xcbc, key);
}

/**
 * Implementation of signer_t.destroy.
 */
static status_t destroy(private_xcbc_signer_t *this)
{
	this->xcbc->destroy(this->xcbc);
	free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
xcbc_signer_t *xcbc_signer_create(integrity_algorithm_t algo)
{
	private_xcbc_signer_t *this;
	size_t trunc;
	xcbc_t *xcbc;

	switch (algo)
	{
		case AUTH_AES_XCBC_96:
			xcbc = xcbc_create(ENCR_AES_CBC, 16);
			trunc = 12;
			break;
		default:
			return NULL;
	}
	if (xcbc == NULL)
	{
		return NULL;
	}

	this = malloc_thing(private_xcbc_signer_t);
	this->xcbc = xcbc;
	this->block_size = min(trunc, xcbc->get_block_size(xcbc));

	/* interface functions */
	this->public.signer_interface.get_signature = (void (*) (signer_t*, chunk_t, u_int8_t*))get_signature;
	this->public.signer_interface.allocate_signature = (void (*) (signer_t*, chunk_t, chunk_t*))allocate_signature;
	this->public.signer_interface.verify_signature = (bool (*) (signer_t*, chunk_t, chunk_t))verify_signature;
	this->public.signer_interface.get_key_size = (size_t (*) (signer_t*))get_key_size;
	this->public.signer_interface.get_block_size = (size_t (*) (signer_t*))get_block_size;
	this->public.signer_interface.set_key = (void (*) (signer_t*,chunk_t))set_key;
	this->public.signer_interface.destroy = (void (*) (signer_t*))destroy;

	return &this->public;
}

