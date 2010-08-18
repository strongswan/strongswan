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

METHOD(signer_t, get_signature, void,
	private_xcbc_signer_t *this, chunk_t data, u_int8_t *buffer)
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

METHOD(signer_t, allocate_signature, void,
	private_xcbc_signer_t *this, chunk_t data, chunk_t *chunk)
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

METHOD(signer_t, verify_signature, bool,
	private_xcbc_signer_t *this, chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->xcbc->get_block_size(this->xcbc)];

	if (signature.len != this->block_size)
	{
		return FALSE;
	}

	this->xcbc->get_mac(this->xcbc, data, mac);
	return memeq(signature.ptr, mac, this->block_size);
}

METHOD(signer_t, get_key_size, size_t,
	private_xcbc_signer_t *this)
{
	return this->xcbc->get_block_size(this->xcbc);
}

METHOD(signer_t, get_block_size, size_t,
	private_xcbc_signer_t *this)
{
	return this->block_size;
}

METHOD(signer_t, set_key, void,
	private_xcbc_signer_t *this, chunk_t key)
{
	this->xcbc->set_key(this->xcbc, key);
}

METHOD(signer_t, destroy, void,
	private_xcbc_signer_t *this)
{
	this->xcbc->destroy(this->xcbc);
	free(this);
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
		case AUTH_CAMELLIA_XCBC_96:
			xcbc = xcbc_create(ENCR_CAMELLIA_CBC, 16);
			trunc = 12;
			break;
		default:
			return NULL;
	}
	if (xcbc == NULL)
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
		.xcbc = xcbc,
		.block_size = min(trunc, xcbc->get_block_size(xcbc)),
	);

	return &this->public;
}

