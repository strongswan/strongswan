/*
 * Copyright (C) 2011 Tobias Brunner
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

#include "keymat_v1.h"

#include <daemon.h>

typedef struct private_keymat_v1_t private_keymat_v1_t;

/**
 * Private data of an keymat_t object.
 */
struct private_keymat_v1_t {

	/**
	 * Public keymat_v1_t interface.
	 */
	keymat_v1_t public;

	/**
	 * IKE_SA Role, initiator or responder
	 */
	bool initiator;

	/**
	 * General purpose PRF
	 */
	prf_t *prf;

	/**
	 * Negotiated PRF algorithm
	 */
	pseudo_random_function_t prf_alg;

};

METHOD(keymat_t, create_dh, diffie_hellman_t*,
	private_keymat_v1_t *this, diffie_hellman_group_t group)
{
	return lib->crypto->create_dh(lib->crypto, group);;
}

METHOD(keymat_t, derive_ike_keys, bool,
	private_keymat_v1_t *this, proposal_t *proposal, diffie_hellman_t *dh,
	chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id,
	pseudo_random_function_t rekey_function, chunk_t rekey_skd)
{
	return FALSE;
}

METHOD(keymat_t, derive_child_keys, bool,
	private_keymat_v1_t *this, proposal_t *proposal, diffie_hellman_t *dh,
	chunk_t nonce_i, chunk_t nonce_r, chunk_t *encr_i, chunk_t *integ_i,
	chunk_t *encr_r, chunk_t *integ_r)
{
	return FALSE;
}

METHOD(keymat_t, get_skd, pseudo_random_function_t,
	private_keymat_v1_t *this, chunk_t *skd)
{
	*skd = chunk_empty;
	return this->prf_alg;
}

METHOD(keymat_t, get_aead, aead_t*,
	private_keymat_v1_t *this, bool in)
{
	return NULL;
}

METHOD(keymat_t, get_auth_octets, chunk_t,
	private_keymat_v1_t *this, bool verify, chunk_t ike_sa_init,
	chunk_t nonce, identification_t *id, char reserved[3])
{
	return chunk_empty;
}

METHOD(keymat_t, get_psk_sig, chunk_t,
	private_keymat_v1_t *this, bool verify, chunk_t ike_sa_init,
	chunk_t nonce, chunk_t secret, identification_t *id, char reserved[3])
{
	return chunk_empty;
}

METHOD(keymat_t, destroy, void,
	private_keymat_v1_t *this)
{
	DESTROY_IF(this->prf);
	free(this);
}

/**
 * See header
 */
keymat_v1_t *keymat_v1_create(bool initiator)
{
	private_keymat_v1_t *this;

	INIT(this,
		.public = {
			.keymat = {
				.create_dh = _create_dh,
				.derive_ike_keys = _derive_ike_keys,
				.derive_child_keys = _derive_child_keys,
				.get_skd = _get_skd,
				.get_aead = _get_aead,
				.get_auth_octets = _get_auth_octets,
				.get_psk_sig = _get_psk_sig,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.prf_alg = PRF_UNDEFINED,
	);

	return &this->public;
}
