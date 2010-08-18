/*
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

#include "hmac.h"


typedef struct private_hmac_prf_t private_hmac_prf_t;

/**
 * Private data of a hma_prf_t object.
 */
struct private_hmac_prf_t {
	/**
	 * Public hmac_prf_t interface.
	 */
	hmac_prf_t public;

	/**
	 * Hmac to use for generation.
	 */
	hmac_t *hmac;
};

METHOD(prf_t, get_bytes, void,
	private_hmac_prf_t *this, chunk_t seed, u_int8_t *buffer)
{
	this->hmac->get_mac(this->hmac, seed, buffer);
}

METHOD(prf_t, allocate_bytes, void,
	private_hmac_prf_t *this, chunk_t seed, chunk_t *chunk)
{
	this->hmac->allocate_mac(this->hmac, seed, chunk);
}

METHOD(prf_t, get_block_size, size_t,
	private_hmac_prf_t *this)
{
	return this->hmac->get_block_size(this->hmac);
}

METHOD(prf_t, get_key_size, size_t,
	private_hmac_prf_t *this)
{
	/* for HMAC prfs, IKEv2 uses block size as key size */
	return this->hmac->get_block_size(this->hmac);
}

METHOD(prf_t, set_key, void,
	private_hmac_prf_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(prf_t, destroy, void,
	private_hmac_prf_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header.
 */
hmac_prf_t *hmac_prf_create(pseudo_random_function_t algo)
{
	private_hmac_prf_t *this;
	hmac_t *hmac;

	switch (algo)
	{
		case PRF_HMAC_SHA1:
			hmac = hmac_create(HASH_SHA1);
			break;
		case PRF_HMAC_MD5:
			hmac = hmac_create(HASH_MD5);
			break;
		case PRF_HMAC_SHA2_256:
			hmac = hmac_create(HASH_SHA256);
			break;
		case PRF_HMAC_SHA2_384:
			hmac = hmac_create(HASH_SHA384);
			break;
		case PRF_HMAC_SHA2_512:
			hmac = hmac_create(HASH_SHA512);
			break;
		default:
			return NULL;
	}
	if (hmac == NULL)
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
		.hmac = hmac,
	);

	return &this->public;
}

