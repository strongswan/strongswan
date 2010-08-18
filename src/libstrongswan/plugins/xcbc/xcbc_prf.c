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

#include "xcbc_prf.h"

#include "xcbc.h"

typedef struct private_xcbc_prf_t private_xcbc_prf_t;

/**
 * Private data of a xcbc_prf_t object.
 */
struct private_xcbc_prf_t {

	/**
	 * Public xcbc_prf_t interface.
	 */
	xcbc_prf_t public;

	/**
	 * xcbc to use for generation.
	 */
	xcbc_t *xcbc;
};

METHOD(prf_t, get_bytes, void,
	private_xcbc_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->xcbc->get_mac(this->xcbc, seed, buffer);
}

METHOD(prf_t, allocate_bytes, void,
	private_xcbc_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	if (chunk)
	{
		*chunk = chunk_alloc(this->xcbc->get_block_size(this->xcbc));
		get_bytes(this, seed, chunk->ptr);
	}
	else
	{
		get_bytes(this, seed, NULL);
	}
}

METHOD(prf_t, get_block_size, size_t,
	private_xcbc_prf_t *this)
{
	return this->xcbc->get_block_size(this->xcbc);
}

METHOD(prf_t, get_key_size, size_t,
	private_xcbc_prf_t *this)
{
	/* in xcbc, block and key size are always equal */
	return this->xcbc->get_block_size(this->xcbc);
}

METHOD(prf_t, set_key, void,
	private_xcbc_prf_t *this, chunk_t key)
{
	this->xcbc->set_key(this->xcbc, key);
}

METHOD(prf_t, destroy, void,
	private_xcbc_prf_t *this)
{
	this->xcbc->destroy(this->xcbc);
	free(this);
}

/*
 * Described in header.
 */
xcbc_prf_t *xcbc_prf_create(pseudo_random_function_t algo)
{
	private_xcbc_prf_t *this;
	xcbc_t *xcbc;

	switch (algo)
	{
		case PRF_AES128_XCBC:
			xcbc = xcbc_create(ENCR_AES_CBC, 16);
			break;
		case PRF_CAMELLIA128_XCBC:
			xcbc = xcbc_create(ENCR_CAMELLIA_CBC, 16);
			break;
		default:
			return NULL;
	}
	if (!xcbc)
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
		.xcbc = xcbc,
	);

	return &this->public;
}

