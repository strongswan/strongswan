/*
 * Copyright (C) 2005-2008 Martin Willi
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

#include <string.h>

#include "hmac_signer.h"
#include "hmac.h"

typedef struct private_hmac_signer_t private_hmac_signer_t;

/**
 * Private data structure with signing context.
 */
struct private_hmac_signer_t {
	/**
	 * Public interface of hmac_signer_t.
	 */
	hmac_signer_t public;

	/**
	 * Assigned hmac function.
	 */
	hmac_t *hmac;

	/**
	 * Block size (truncation of HMAC Hash)
	 */
	size_t block_size;
};

METHOD(signer_t, get_signature, void,
	private_hmac_signer_t *this, chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{	/* append mode */
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);
		memcpy(buffer, mac, this->block_size);
	}
}

METHOD(signer_t, allocate_signature, void,
	private_hmac_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{	/* append mode */
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_block_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);

		chunk->ptr = malloc(this->block_size);
		chunk->len = this->block_size;

		memcpy(chunk->ptr, mac, this->block_size);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_hmac_signer_t *this, chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->hmac->get_block_size(this->hmac)];

	this->hmac->get_mac(this->hmac, data, mac);

	if (signature.len != this->block_size)
	{
		return FALSE;
	}
	return memeq(signature.ptr, mac, this->block_size);
}

METHOD(signer_t, get_key_size, size_t,
	private_hmac_signer_t *this)
{
	return this->hmac->get_block_size(this->hmac);
}

METHOD(signer_t, get_block_size, size_t,
	private_hmac_signer_t *this)
{
	return this->block_size;
}

METHOD(signer_t, set_key, void,
	private_hmac_signer_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(signer_t, destroy, void,
	private_hmac_signer_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header
 */
hmac_signer_t *hmac_signer_create(integrity_algorithm_t algo)
{
	private_hmac_signer_t *this;
	hmac_t *hmac;
	size_t trunc;

	switch (algo)
	{
		case AUTH_HMAC_SHA1_96:
			hmac = hmac_create(HASH_SHA1);
			trunc = 12;
			break;
		case AUTH_HMAC_SHA1_128:
			hmac = hmac_create(HASH_SHA1);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA1_160:
			hmac = hmac_create(HASH_SHA1);
			trunc = 20;
			break;
		case AUTH_HMAC_MD5_96:
			hmac = hmac_create(HASH_MD5);
			trunc = 12;
			break;
		case AUTH_HMAC_MD5_128:
			hmac = hmac_create(HASH_MD5);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_256_128:
			hmac = hmac_create(HASH_SHA256);
			trunc = 16;
			break;
		case AUTH_HMAC_SHA2_384_192:
			hmac = hmac_create(HASH_SHA384);
			trunc = 24;
			break;
		case AUTH_HMAC_SHA2_512_256:
			hmac = hmac_create(HASH_SHA512);
			trunc = 32;
			break;
		case AUTH_HMAC_SHA2_256_256:
			hmac = hmac_create(HASH_SHA256);
			trunc = 32;
			break;
		case AUTH_HMAC_SHA2_384_384:
			hmac = hmac_create(HASH_SHA384);
			trunc = 48;
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
			.signer = {
				.get_signature = _get_signature,
				.allocate_signature = _allocate_signature,
				.verify_signature = _verify_signature,
				.get_key_size = _get_key_size,
				.get_block_size = _get_block_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.block_size = min(trunc, hmac->get_block_size(hmac)),
		.hmac = hmac,
	);

	return &this->public;
}

