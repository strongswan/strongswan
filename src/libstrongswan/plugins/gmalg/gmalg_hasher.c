/*
 * Copyright (C) 2008-2017 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include <gmalg.h>

#include "gmalg_hasher.h"

typedef struct private_gmalg_hasher_t private_gmalg_hasher_t;

/**
 * Private data of gmalg_hasher_t
 */
struct private_gmalg_hasher_t {

	/**
	 * Public part of this class.
	 */
	gmalg_hasher_t public;

	/**
	 * the hasher to use
	 */
	hash_algorithm_t algo;

	/*
	 * the cipher device handle
	 */
	void *hDeviceHandle;

};

METHOD(hasher_t, get_hash_size, size_t,
	private_gmalg_hasher_t *this)
{
	return HASH_SIZE_SM3;
}

METHOD(hasher_t, reset, bool,
	private_gmalg_hasher_t *this)
{
	bool rc = TRUE;

	GMALG_HashInit(this->hDeviceHandle, NULL, NULL, 0);

	return rc;
}

METHOD(hasher_t, get_hash, bool,
	private_gmalg_hasher_t *this, chunk_t chunk, uint8_t *hash)
{
	GMALG_HashUpdate(this->hDeviceHandle, chunk.ptr, chunk.len);

	if (hash)
	{
		u_int len;
		GMALG_HashFinal(this->hDeviceHandle, hash, &len);
		GMALG_HashInit(this->hDeviceHandle, NULL, NULL, 0);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_gmalg_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(get_hash_size(this));
		return get_hash(this, chunk, hash->ptr);
	}
	return get_hash(this, chunk, NULL);
}

METHOD(hasher_t, destroy, void,
	private_gmalg_hasher_t *this)
{
	GMALG_CloseDevice(this->hDeviceHandle);
	free(this);
}

/*
 * Described in header
 */
gmalg_hasher_t *gmalg_hasher_create(hash_algorithm_t algo)
{
	private_gmalg_hasher_t *this;

	INIT(this,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	this->algo = algo;
	GMALG_OpenDevice(&this->hDeviceHandle);
	GMALG_HashInit(this->hDeviceHandle, NULL, NULL, 0);

	return &this->public;
}

gmalg_hasher_t *gmalg_hasher_create_ecc(hash_algorithm_t algo, ECCrefPublicKey *pub_key, chunk_t id)
{
	private_gmalg_hasher_t *this;

	INIT(this,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	this->algo = algo;
	GMALG_OpenDevice(&this->hDeviceHandle);
	GMALG_HashInit(this->hDeviceHandle, pub_key, id.ptr, id.len);

	return &this->public;
}
