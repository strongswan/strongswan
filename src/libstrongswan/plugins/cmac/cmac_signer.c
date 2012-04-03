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

#include <string.h>

#include "cmac_signer.h"
#include "cmac.h"

typedef struct private_cmac_signer_t private_cmac_signer_t;

/**
 * Private data structure with signing context.
 */
struct private_cmac_signer_t {

	/**
	 * Public interface.
	 */
	cmac_signer_t public;

	/**
	 * Assigned cmac function.
	 */
	cmac_t *cmac;

	/**
	 * Block size (truncation of CMAC MAC)
	 */
	size_t block_size;
};

METHOD(signer_t, get_signature, void,
	private_cmac_signer_t *this, chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{	/* append mode */
		this->cmac->get_mac(this->cmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->cmac->get_block_size(this->cmac)];

		this->cmac->get_mac(this->cmac, data, mac);
		memcpy(buffer, mac, this->block_size);
	}
}

METHOD(signer_t, allocate_signature, void,
	private_cmac_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{	/* append mode */
		this->cmac->get_mac(this->cmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->cmac->get_block_size(this->cmac)];

		this->cmac->get_mac(this->cmac, data, mac);

		chunk->ptr = malloc(this->block_size);
		chunk->len = this->block_size;

		memcpy(chunk->ptr, mac, this->block_size);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_cmac_signer_t *this, chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->cmac->get_block_size(this->cmac)];

	if (signature.len != this->block_size)
	{
		return FALSE;
	}

	this->cmac->get_mac(this->cmac, data, mac);
	return memeq(signature.ptr, mac, this->block_size);
}

METHOD(signer_t, get_key_size, size_t,
	private_cmac_signer_t *this)
{
	return this->cmac->get_block_size(this->cmac);
}

METHOD(signer_t, get_block_size, size_t,
	private_cmac_signer_t *this)
{
	return this->block_size;
}

METHOD(signer_t, set_key, void,
	private_cmac_signer_t *this, chunk_t key)
{
	this->cmac->set_key(this->cmac, key);
}

METHOD(signer_t, destroy, void,
	private_cmac_signer_t *this)
{
	this->cmac->destroy(this->cmac);
	free(this);
}

/*
 * Described in header
 */
cmac_signer_t *cmac_signer_create(integrity_algorithm_t algo)
{
	private_cmac_signer_t *this;
	size_t truncation;
	cmac_t *cmac;

	switch (algo)
	{
		case AUTH_AES_CMAC_96:
			cmac = cmac_create(ENCR_AES_CBC, 16);
			truncation = 12;
			break;
		default:
			return NULL;
	}
	if (cmac == NULL)
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
		.cmac = cmac,
		.block_size = min(truncation, cmac->get_block_size(cmac)),
	);

	return &this->public;
}
