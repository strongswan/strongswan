/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "hmac_prf.h"

typedef struct private_prf_t private_prf_t;

/**
 * Private data of a hmac_prf_t object.
 */
struct private_prf_t {

	/**
	 * Public interface
	 */
	prf_t public;

	/**
	 * HMAC to use
	 */
	hmac_t *hmac;
};

METHOD(prf_t, get_bytes, void,
	private_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->hmac->get_mac(this->hmac, seed, buffer);
}

METHOD(prf_t, allocate_bytes, void,
	private_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	if (!chunk)
	{
		this->hmac->get_mac(this->hmac, seed, NULL);
	}
	else
	{
		*chunk = chunk_alloc(this->hmac->get_mac_size(this->hmac));
		this->hmac->get_mac(this->hmac, seed, chunk->ptr);
	}
}

METHOD(prf_t, get_block_size, size_t,
	private_prf_t *this)
{
	return this->hmac->get_mac_size(this->hmac);
}

METHOD(prf_t, get_key_size, size_t,
	private_prf_t *this)
{
	/* for HMAC PRFs, IKEv2 uses MAC size as key size */
	return this->hmac->get_mac_size(this->hmac);
}

METHOD(prf_t, set_key, void,
	private_prf_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(prf_t, destroy, void,
	private_prf_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header.
 */
prf_t *hmac_prf_create(hmac_t *hmac)
{
	private_prf_t *this;

	INIT(this,
		.public = {
			.get_bytes = _get_bytes,
			.allocate_bytes = _allocate_bytes,
			.get_block_size = _get_block_size,
			.get_key_size = _get_key_size,
			.set_key = _set_key,
			.destroy = _destroy,
		},
		.hmac = hmac,
	);

	return &this->public;
}
