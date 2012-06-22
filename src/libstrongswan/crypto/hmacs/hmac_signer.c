/*
 * Copyright (C) 2012 Tobias Brunner
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

#include "hmac_signer.h"

typedef struct private_signer_t private_signer_t;

/**
 * Private data of a hmac_signer_t object.
 */
struct private_signer_t {

	/**
	 * Public interface
	 */
	signer_t public;

	/**
	 * HMAC to use
	 */
	hmac_t *hmac;

	/**
	 * Truncation of HMAC output
	 */
	size_t truncation;
};

METHOD(signer_t, get_signature, void,
	private_signer_t *this, chunk_t data, u_int8_t *buffer)
{
	if (buffer == NULL)
	{
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_mac_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);
		memcpy(buffer, mac, this->truncation);
	}
}

METHOD(signer_t, allocate_signature, void,
	private_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk == NULL)
	{
		this->hmac->get_mac(this->hmac, data, NULL);
	}
	else
	{
		u_int8_t mac[this->hmac->get_mac_size(this->hmac)];

		this->hmac->get_mac(this->hmac, data, mac);

		*chunk = chunk_alloc(this->truncation);
		memcpy(chunk->ptr, mac, this->truncation);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_signer_t *this, chunk_t data, chunk_t signature)
{
	u_int8_t mac[this->hmac->get_mac_size(this->hmac)];

	if (signature.len != this->truncation)
	{
		return FALSE;
	}
	this->hmac->get_mac(this->hmac, data, mac);
	return memeq(signature.ptr, mac, this->truncation);
}

METHOD(signer_t, get_key_size, size_t,
	private_signer_t *this)
{
	return this->hmac->get_mac_size(this->hmac);
}

METHOD(signer_t, get_block_size, size_t,
	private_signer_t *this)
{
	return this->truncation;
}

METHOD(signer_t, set_key, void,
	private_signer_t *this, chunk_t key)
{
	this->hmac->set_key(this->hmac, key);
}

METHOD(signer_t, destroy, void,
	private_signer_t *this)
{
	this->hmac->destroy(this->hmac);
	free(this);
}

/*
 * Described in header
 */
signer_t *hmac_signer_create(hmac_t *hmac, size_t len)
{
	private_signer_t *this;

	INIT(this,
		.public = {
			.get_signature = _get_signature,
			.allocate_signature = _allocate_signature,
			.verify_signature = _verify_signature,
			.get_block_size = _get_block_size,
			.get_key_size = _get_key_size,
			.set_key = _set_key,
			.destroy = _destroy,
		},
		.truncation = min(len, hmac->get_mac_size(hmac)),
		.hmac = hmac,
	);

	return &this->public;
}

