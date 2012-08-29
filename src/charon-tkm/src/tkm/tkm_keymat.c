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
#include <tkm/constants.h>
#include <tkm/client.h>

#include "tkm.h"
#include "tkm_utils.h"
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
	 * IKE_SA Role, initiator or responder.
	 */
	bool initiator;

	/**
	 * Inbound AEAD.
	 */
	aead_t *aead_in;

	/**
	 * Outbound AEAD.
	 */
	aead_t *aead_out;

};

/**
 * Create AEAD transforms from given key chunks.
 *
 * @param in			inbound AEAD transform to allocate, NULL if failed
 * @param out			outbound AEAD transform to allocate, NULL if failed
 * @param sk_ai			SK_ai key chunk
 * @param sk_ar			SK_ar key chunk
 * @param sk_ei			SK_ei key chunk
 * @param sk_er			SK_er key chunk
 * @param enc_alg		encryption algorithm to use
 * @param int_alg		integrity algorithm to use
 * @param key_size		encryption key size in bytes
 * @param initiator		TRUE if initiator
 */
static void aead_create_from_keys(aead_t **in, aead_t **out,
	   const chunk_t * const sk_ai, const chunk_t * const sk_ar,
	   const chunk_t * const sk_ei, const chunk_t * const sk_er,
	   const u_int16_t enc_alg, const u_int16_t int_alg,
	   const u_int16_t key_size, bool initiator)
{
	*in = *out = NULL;

	signer_t * const signer_i = lib->crypto->create_signer(lib->crypto, int_alg);
	signer_t * const signer_r = lib->crypto->create_signer(lib->crypto, int_alg);
	if (signer_i == NULL || signer_r == NULL)
	{
		DBG1(DBG_IKE, "%N %N not supported!",
			 transform_type_names, INTEGRITY_ALGORITHM,
			 integrity_algorithm_names, int_alg);
		return;
	}
	crypter_t * const crypter_i = lib->crypto->create_crypter(lib->crypto,
			enc_alg, key_size);
	crypter_t * const crypter_r = lib->crypto->create_crypter(lib->crypto,
			enc_alg, key_size);
	if (crypter_i == NULL || crypter_r == NULL)
	{
		signer_i->destroy(signer_i);
		signer_r->destroy(signer_r);
		DBG1(DBG_IKE, "%N %N (key size %d) not supported!",
			 transform_type_names, ENCRYPTION_ALGORITHM,
			 encryption_algorithm_names, enc_alg, key_size);
		return;
	}

	DBG4(DBG_IKE, "Sk_ai %B", sk_ai);
	if (!signer_i->set_key(signer_i, *sk_ai))
	{
		return;
	}
	DBG4(DBG_IKE, "Sk_ar %B", sk_ar);
	if (!signer_r->set_key(signer_r, *sk_ar))
	{
		return;
	}
	DBG4(DBG_IKE, "Sk_ei %B", sk_ei);
	if (!crypter_i->set_key(crypter_i, *sk_ei))
	{
		return;
	}
	DBG4(DBG_IKE, "Sk_er %B", sk_er);
	if (!crypter_r->set_key(crypter_r, *sk_er))
	{
		return;
	}

	if (initiator)
	{
		*in = aead_create(crypter_r, signer_r);
		*out = aead_create(crypter_i, signer_i);
	}
	else
	{
		*in = aead_create(crypter_i, signer_i);
		*out = aead_create(crypter_r, signer_r);
	}
}

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
	/* Check encryption and integrity algorithms */
	u_int16_t enc_alg, int_alg, key_size;
	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &enc_alg, &key_size))
	{
		DBG1(DBG_IKE, "no %N selected", transform_type_names,
				ENCRYPTION_ALGORITHM);
		return FALSE;
	}
	if (encryption_algorithm_is_aead(enc_alg))
	{
		DBG1(DBG_IKE, "AEAD algorithm %N not supported",
			   encryption_algorithm_names, enc_alg);
		return FALSE;
	}
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &int_alg, NULL))
	{
		DBG1(DBG_IKE, "no %N selected", transform_type_names,
				INTEGRITY_ALGORITHM);
		return FALSE;
	}
	DBG2(DBG_IKE, "using %N for encryption, %N for integrity",
			encryption_algorithm_names, enc_alg,
			integrity_algorithm_names, int_alg);

	/* Acquire nonce context id */
	chunk_t * const nonce = this->initiator ? &nonce_i : &nonce_r;
	const uint64_t nc_id = tkm->chunk_map->get_id(tkm->chunk_map, nonce);
	if (!nc_id)
	{
		DBG1(DBG_IKE, "unable to acquire context id for nonce");
		return FALSE;
	}

	/* Get DH context id */
	tkm_diffie_hellman_t * const tkm_dh = (tkm_diffie_hellman_t *)dh;
	const dh_id_type dh_id = tkm_dh->get_id(tkm_dh);

	nonce_type nonce_rem;
	u_int64_t spi_loc, spi_rem;

	if (this->initiator)
	{
		chunk_to_sequence(&nonce_r, &nonce_rem);
		spi_loc = id->get_initiator_spi(id);
		spi_rem = id->get_responder_spi(id);
	}
	else
	{
		chunk_to_sequence(&nonce_i, &nonce_rem);
		spi_loc = id->get_responder_spi(id);
		spi_rem = id->get_initiator_spi(id);
	}

	key_type sk_ai, sk_ar, sk_ei, sk_er;
	DBG1(DBG_IKE, "deriving IKE keys (nc: %llu, dh: %llu, spi_loc: %llx, "
			"spi_rem: %llx)", nc_id, dh_id, spi_loc, spi_rem);
	/* Fake some data for now */
	if (ike_isa_create(1, 1, 1, dh_id, nc_id, nonce_rem, 1, spi_loc, spi_rem,
				&sk_ai, &sk_ar, &sk_ei, &sk_er) != TKM_OK)
	{
		DBG1(DBG_IKE, "key derivation failed");
		return FALSE;
	}

	chunk_t c_ai, c_ar, c_ei, c_er;
	sequence_to_chunk(sk_ai.data, sk_ai.size, &c_ai);
	sequence_to_chunk(sk_ar.data, sk_ar.size, &c_ar);
	sequence_to_chunk(sk_ei.data, sk_ei.size, &c_ei);
	sequence_to_chunk(sk_er.data, sk_er.size, &c_er);

	aead_create_from_keys(&this->aead_in, &this->aead_out,
			&c_ai, &c_ar, &c_ei, &c_er,
			enc_alg, int_alg, key_size / 8, this->initiator);

	chunk_clear(&c_ai);
	chunk_clear(&c_ar);
	chunk_clear(&c_ei);
	chunk_clear(&c_er);

	if (!this->aead_in || !this->aead_out)
	{
		DBG1(DBG_IKE, "could not initialize AEAD transforms");
		return FALSE;
	}

	/* TODO: Add failure handler (see keymat_v2.c) */

	if (this->proxy->derive_ike_keys(this->proxy, proposal, dh, nonce_i,
				nonce_r, id, rekey_function, rekey_skd))
	{
		tkm->chunk_map->remove(tkm->chunk_map, nonce);
		if (ike_nc_reset(nc_id) != TKM_OK)
		{
			DBG1(DBG_IKE, "failed to reset nonce context %llu", nc_id);
		}
		tkm->idmgr->release_id(tkm->idmgr, TKM_CTX_NONCE, nc_id);

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
	return in ? this->aead_in : this->aead_out;
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
	if (!verify)
	{
		signature_type signature;
		init_message_type msg;
		chunk_to_sequence(&ike_sa_init, &msg);

		chunk_t idx_chunk, chunk = chunk_alloca(4);
		chunk.ptr[0] = id->get_type(id);
		memcpy(chunk.ptr + 1, reserved, 3);
		idx_chunk = chunk_cata("cc", chunk, id->get_encoding(id));
		idx_type idx;
		chunk_to_sequence(&idx_chunk, &idx);

		if (ike_isa_sign_psk(1, msg, idx, &signature) != TKM_OK)
		{
			DBG1(DBG_IKE, "get local PSK signature failed");
			return FALSE;
		}

		sequence_to_chunk(&signature.data[0], signature.size, sig);
		return TRUE;
	}
	else
	{
		return this->proxy->get_psk_sig(this->proxy, verify, ike_sa_init, nonce,
			secret, id, reserved, sig);
	}
}

METHOD(keymat_t, destroy, void,
	private_tkm_keymat_t *this)
{
	DESTROY_IF(this->aead_in);
	DESTROY_IF(this->aead_out);
	this->proxy->keymat.destroy(&this->proxy->keymat);
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
