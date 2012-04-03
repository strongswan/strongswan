/*
 * Copyright (C) 2012 Tobias Brunner
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

#include "cmac_prf.h"

#include "cmac.h"

typedef struct private_cmac_prf_t private_cmac_prf_t;

/**
 * Private data of a cmac_prf_t object.
 */
struct private_cmac_prf_t {

	/**
	 * Public cmac_prf_t interface.
	 */
	cmac_prf_t public;

	/**
	 * cmac to use for generation.
	 */
	cmac_t *cmac;
};

METHOD(prf_t, get_bytes, void,
	private_cmac_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->cmac->get_mac(this->cmac, seed, buffer);
}

METHOD(prf_t, allocate_bytes, void,
	private_cmac_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	if (chunk)
	{
		*chunk = chunk_alloc(this->cmac->get_block_size(this->cmac));
		get_bytes(this, seed, chunk->ptr);
	}
	else
	{
		get_bytes(this, seed, NULL);
	}
}

METHOD(prf_t, get_block_size, size_t,
	private_cmac_prf_t *this)
{
	return this->cmac->get_block_size(this->cmac);
}

METHOD(prf_t, get_key_size, size_t,
	private_cmac_prf_t *this)
{
	/* in cmac, block and key size are always equal */
	return this->cmac->get_block_size(this->cmac);
}

METHOD(prf_t, set_key, void,
	private_cmac_prf_t *this, chunk_t key)
{
	this->cmac->set_key(this->cmac, key);
}

METHOD(prf_t, destroy, void,
	private_cmac_prf_t *this)
{
	this->cmac->destroy(this->cmac);
	free(this);
}

/*
 * Described in header.
 */
cmac_prf_t *cmac_prf_create(pseudo_random_function_t algo)
{
	private_cmac_prf_t *this;
	cmac_t *cmac;

	switch (algo)
	{
		case PRF_AES128_CMAC:
			cmac = cmac_create(ENCR_AES_CBC, 16);
			break;
		default:
			return NULL;
	}
	if (!cmac)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.prf = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.get_block_size = _get_block_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.cmac = cmac,
	);

	return &this->public;
}

