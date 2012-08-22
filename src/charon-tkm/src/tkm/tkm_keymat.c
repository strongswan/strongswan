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

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>

#include "tkm.h"
#include "tkm_diffie_hellman.h"
#include "tkm_keymat.h"

typedef struct private_tkm_keymat_t private_tkm_keymat_t;

/**
 * Private data of a keymat_t object.
 */
struct private_tkm_keymat_t {

	/**
	 * Public tkm_keymat_t interface.
	 */
	tkm_keymat_t public;

	/**
	 * IKEv2 keymat proxy (will be removed).
	 */
	keymat_v2_t *proxy;

	/**
	 * IKE_SA Role, initiator or responder
	 */
	bool initiator;

};

METHOD(keymat_t, get_version, ike_version_t,
	private_tkm_keymat_t *this)
{
	return IKEV2;
}

METHOD(keymat_t, create_dh, diffie_hellman_t*,
	private_tkm_keymat_t *this, diffie_hellman_group_t group)
{
	return lib->crypto->create_dh(lib->crypto, group);
}

METHOD(keymat_t, create_nonce_gen, nonce_gen_t*,
	private_tkm_keymat_t *this)
{
	return lib->crypto->create_nonce_gen(lib->crypto);
}

METHOD(tkm_keymat_t, derive_ike_keys, bool,
	private_tkm_keymat_t *this, proposal_t *proposal, diffie_hellman_t *dh,
	chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id,
	pseudo_random_function_t rekey_function, chunk_t rekey_skd)
{
	tkm_diffie_hellman_t * const tkm_dh = (tkm_diffie_hellman_t *)dh;
	chunk_t * const nonce = this->initiator ? &nonce_i : &nonce_r;

	const uint64_t nc_id = tkm->chunk_map->get_id(tkm->chunk_map, nonce);
	if (!nc_id)
	{
		DBG1(DBG_IKE, "unable to acquire context id for nonce");
		return FALSE;
	}

	DBG1(DBG_IKE, "deriving IKE keys (nc: %llu, dh: %llu)", nc_id,
			tkm_dh->get_id(tkm_dh));
	if (this->proxy->derive_ike_keys(this->proxy, proposal, dh, nonce_i,
				nonce_r, id, rekey_function, rekey_skd))
	{
		tkm->chunk_map->remove(tkm->chunk_map, nonce);
		return TRUE;
	}
	return FALSE;
}

METHOD(tkm_keymat_t, derive_child_keys, bool,
	private_tkm_keymat_t *this, proposal_t *proposal, diffie_hellman_t *dh,
	chunk_t nonce_i, chunk_t nonce_r, chunk_t *encr_i, chunk_t *integ_i,
	chunk_t *encr_r, chunk_t *integ_r)
{
	DBG1(DBG_CHD, "deriving child keys");
	return this->proxy->derive_child_keys(this->proxy, proposal, dh, nonce_i,
			nonce_r, encr_i, integ_i, encr_r, integ_r);
}

METHOD(keymat_t, get_aead, aead_t*,
	private_tkm_keymat_t *this, bool in)
{
	DBG1(DBG_IKE, "returning aead transform");
	return this->proxy->keymat.get_aead(&this->proxy->keymat, in);
}

METHOD(tkm_keymat_t, get_auth_octets, bool,
	private_tkm_keymat_t *this, bool verify, chunk_t ike_sa_init,
	chunk_t nonce, identification_t *id, char reserved[3], chunk_t *octets)
{
	DBG1(DBG_IKE, "returning auth octets");
	return this->proxy->get_auth_octets(this->proxy, verify, ike_sa_init, nonce,
			id, reserved, octets);
}

METHOD(tkm_keymat_t, get_skd, pseudo_random_function_t,
	private_tkm_keymat_t *this, chunk_t *skd)
{
	DBG1(DBG_IKE, "returning skd");
	return this->proxy->get_skd(this->proxy, skd);
}

METHOD(tkm_keymat_t, get_psk_sig, bool,
	private_tkm_keymat_t *this, bool verify, chunk_t ike_sa_init, chunk_t nonce,
	chunk_t secret, identification_t *id, char reserved[3], chunk_t *sig)
{
	DBG1(DBG_IKE, "returning PSK signature");
	return this->proxy->get_psk_sig(this->proxy, verify, ike_sa_init, nonce,
			secret, id, reserved, sig);
}

METHOD(keymat_t, destroy, void,
	private_tkm_keymat_t *this)
{
	free(this);
}

/**
 * See header.
 */
tkm_keymat_t *tkm_keymat_create(bool initiator)
{
	private_tkm_keymat_t *this;

	INIT(this,
		.public = {
			.keymat = {
				.get_version = _get_version,
				.create_dh = _create_dh,
				.create_nonce_gen = _create_nonce_gen,
				.get_aead = _get_aead,
				.destroy = _destroy,
			},
			.derive_ike_keys = _derive_ike_keys,
			.derive_child_keys = _derive_child_keys,
			.get_skd = _get_skd,
			.get_auth_octets = _get_auth_octets,
			.get_psk_sig = _get_psk_sig,
		},
		.initiator = initiator,
		.proxy = keymat_v2_create(initiator),
	);

	return &this->public;
}
