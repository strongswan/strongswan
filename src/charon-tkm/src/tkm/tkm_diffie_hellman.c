/*
 * Copyrigth (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <tkm/client.h>
#include <tkm/constants.h>

#include "tkm_diffie_hellman.h"

#include <utils/debug.h>

typedef struct private_tkm_diffie_hellman_t private_tkm_diffie_hellman_t;

/**
 * Private data of a tkm_diffie_hellman_t object.
 */
struct private_tkm_diffie_hellman_t {
	/**
	 * Public tkm_diffie_hellman_t interface.
	 */
	tkm_diffie_hellman_t public;

	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t group;

	/**
	 * Diffie Hellman public value.
	 */
	dh_pubvalue_type pubvalue;
};

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_tkm_diffie_hellman_t *this, chunk_t *value)
{
	*value = chunk_alloc(this->pubvalue.size);
	memcpy(value->ptr, &this->pubvalue.data, value->len);
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_tkm_diffie_hellman_t *this, chunk_t *secret)
{
	dh_key_type shared_secret;
	if (ike_dh_get_shared_secret(1, &shared_secret) != TKM_OK)
	{
		return FAILED;
	}

	*secret = chunk_alloc(shared_secret.size);
	memcpy(secret->ptr, &shared_secret.data, secret->len);
	return SUCCESS;
}


METHOD(diffie_hellman_t, set_other_public_value, void,
	private_tkm_diffie_hellman_t *this, chunk_t value)
{
	// TODO: unvoid this function

	dh_pubvalue_type othervalue;
	othervalue.size = value.len;
	memcpy(&othervalue.data, value.ptr, value.len);

	ike_dh_generate_key(1, othervalue);
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_tkm_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_tkm_diffie_hellman_t *this)
{
	// TODO: unvoid this function

	free(this);
	if (ike_dh_reset(1) != TKM_OK)
	{
		DBG1(DBG_LIB, "resetting DH context 1 failed");
	}
}

/*
 * Described in header.
 */
tkm_diffie_hellman_t *tkm_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_tkm_diffie_hellman_t *this;

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
	);

	if (ike_dh_create(1, group, &this->pubvalue) != TKM_OK)
	{
		free(this);
		return NULL;
	}

	this->group = group;

	return &this->public;
}
