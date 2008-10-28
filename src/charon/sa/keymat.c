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
 *
 * $Id$
 */

#include "keymat.h"

#include <daemon.h>
#include <crypto/prf_plus.h>

typedef struct private_keymat_t private_keymat_t;

/**
 * Private data of an keymat_t object.
 */
struct private_keymat_t {
	
	/**
	 * Public keymat_t interface.
	 */
	keymat_t public;
	
	/**
 	 * IKE_SA Role, initiator or responder
 	 */
 	bool initiator;
	
	/**
	 * diffie hellman key exchange
	 */
	diffie_hellman_t *dh;
	
	/**
	 * inbound signer (verify)
	 */
	signer_t *signer_in;
	
	/**
	 * outbound signer (sign)
	 */
	signer_t *signer_out;
	
	/**
	 * inbound crypter (decrypt)
	 */
	crypter_t *crypter_in;
	
	/**
	 * outbound crypter (encrypt)
	 */
	crypter_t *crypter_out;
	
	/**
	 * General purpose PRF
	 */
	prf_t *prf;
	
	/**
	 * PRF for CHILD_SA keymat
	 */
	prf_t *child_prf;
	
	/**
	 * Key to build outging authentication data (SKp)
	 */
	chunk_t skp_build;

	/**
	 * Key to verify incoming authentication data (SKp)
	 */
	chunk_t skp_verify;
	
	/**
	 * Negotiated IKE proposal
	 */
	proposal_t *proposal;
};

/**
 * Implementation of keymat_t.set_dh_group
 */
static bool set_dh_group(private_keymat_t *this, diffie_hellman_group_t group)
{
	DESTROY_IF(this->dh);
	this->dh = lib->crypto->create_dh(lib->crypto, group);
	return this->dh != NULL;
}

/**
 * Implementation of keymat_t.get_dh
 */
static diffie_hellman_t* get_dh(private_keymat_t *this)
{
	return this->dh;
}

/**
 * Implementation of keymat_t.derive_keys
 */
static bool derive_keys(private_keymat_t *this, proposal_t *proposal,
						chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id,
						private_keymat_t *rekey)
{
	chunk_t skeyseed, key, secret, full_nonce, fixed_nonce, prf_plus_seed;
	chunk_t spi_i, spi_r;
	crypter_t *crypter_i, *crypter_r;
	signer_t *signer_i, *signer_r;
	prf_plus_t *prf_plus;
	u_int16_t alg, key_size;
	
	spi_i = chunk_alloca(sizeof(u_int64_t));
	spi_r = chunk_alloca(sizeof(u_int64_t));
	
	if (!this->dh || this->dh->get_shared_secret(this->dh, &secret) != SUCCESS)
	{
		return FALSE;
	}
	
	/* Create SAs general purpose PRF first, we may use it here */
	if (!proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{
		DBG1(DBG_IKE, "no %N selected",
			 transform_type_names, PSEUDO_RANDOM_FUNCTION);
		return FALSE;
	}
	this->prf = lib->crypto->create_prf(lib->crypto, alg);
	if (this->prf == NULL)
	{
		DBG1(DBG_IKE, "%N %N not supported!",
			 transform_type_names, PSEUDO_RANDOM_FUNCTION,
			 pseudo_random_function_names, alg);
		return FALSE;
	}
	DBG4(DBG_IKE, "shared Diffie Hellman secret %B", &secret);
	/* full nonce is used as seed for PRF+ ... */
	full_nonce = chunk_cat("cc", nonce_i, nonce_r);
	/* but the PRF may need a fixed key which only uses the first bytes of
	 * the nonces. */
	switch (alg)
	{
		case PRF_AES128_XCBC:
			/* while rfc4434 defines variable keys for AES-XCBC, rfc3664 does
			 * not and therefore fixed key semantics apply to XCBC for key
			 * derivation. */
			nonce_i.len = min(nonce_i.len, this->prf->get_key_size(this->prf)/2);
			nonce_r.len = min(nonce_r.len, this->prf->get_key_size(this->prf)/2);
			break;
		default:
			/* all other algorithms use variable key length, full nonce */
			break;
	}
	fixed_nonce = chunk_cat("cc", nonce_i, nonce_r);
	*((u_int64_t*)spi_i.ptr) = id->get_initiator_spi(id);
	*((u_int64_t*)spi_r.ptr) = id->get_responder_spi(id);
	prf_plus_seed = chunk_cat("ccc", full_nonce, spi_i, spi_r);
	
	/* KEYMAT = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) 
	 *
	 * if we are rekeying, SKEYSEED is built on another way
	 */
	if (rekey == NULL) /* not rekeying */
	{
		/* SKEYSEED = prf(Ni | Nr, g^ir) */
		this->prf->set_key(this->prf, fixed_nonce);
		this->prf->allocate_bytes(this->prf, secret, &skeyseed);
		DBG4(DBG_IKE, "SKEYSEED %B", &skeyseed);
		this->prf->set_key(this->prf, skeyseed);
		chunk_clear(&skeyseed);
		chunk_clear(&secret);
		prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	}
	else
	{
		/* SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr) 
		 * use OLD SAs PRF functions for both prf_plus and prf */
		secret = chunk_cat("mc", secret, full_nonce);
		rekey->child_prf->allocate_bytes(rekey->child_prf, secret, &skeyseed);
		DBG4(DBG_IKE, "SKEYSEED %B", &skeyseed);
		rekey->prf->set_key(rekey->prf, skeyseed);
		chunk_clear(&skeyseed);
		chunk_clear(&secret);
		prf_plus = prf_plus_create(rekey->prf, prf_plus_seed);
	}
	chunk_free(&full_nonce);
	chunk_free(&fixed_nonce);
	chunk_clear(&prf_plus_seed);
	
	/* KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr */
	
	/* SK_d is used for generating CHILD_SA key mat => child_prf */
	proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL);
	this->child_prf = lib->crypto->create_prf(lib->crypto, alg);
	key_size = this->child_prf->get_key_size(this->child_prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_d secret %B", &key);
	this->child_prf->set_key(this->child_prf, key);
	chunk_clear(&key);
	
	/* SK_ai/SK_ar used for integrity protection => signer_in/signer_out */
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		DBG1(DBG_IKE, "no %N selected",
			 transform_type_names, INTEGRITY_ALGORITHM);
		return FALSE;
	}
	signer_i = lib->crypto->create_signer(lib->crypto, alg);
	signer_r = lib->crypto->create_signer(lib->crypto, alg);
	if (signer_i == NULL || signer_r == NULL)
	{
		DBG1(DBG_IKE, "%N %N not supported!",
			 transform_type_names, INTEGRITY_ALGORITHM,
			 integrity_algorithm_names ,alg);
		prf_plus->destroy(prf_plus);
		return FALSE;
	}
	key_size = signer_i->get_key_size(signer_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ai secret %B", &key);
	signer_i->set_key(signer_i, key);
	chunk_clear(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ar secret %B", &key);
	signer_r->set_key(signer_r, key);
	chunk_clear(&key);
	
	if (this->initiator)
	{
		this->signer_in = signer_r;
		this->signer_out = signer_i;
	}
	else
	{
		this->signer_in = signer_i;
		this->signer_out = signer_r;
	}
	
	/* SK_ei/SK_er used for encryption => crypter_in/crypter_out */
	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &key_size))
	{
		DBG1(DBG_IKE, "no %N selected",
			 transform_type_names, ENCRYPTION_ALGORITHM);
		prf_plus->destroy(prf_plus);
		return FALSE;
	}
	crypter_i = lib->crypto->create_crypter(lib->crypto, alg, key_size / 8);
	crypter_r = lib->crypto->create_crypter(lib->crypto, alg, key_size / 8);
	if (crypter_i == NULL || crypter_r == NULL)
	{
		DBG1(DBG_IKE, "%N %N (key size %d) not supported!",
			 transform_type_names, ENCRYPTION_ALGORITHM,
			 encryption_algorithm_names, alg, key_size);
		prf_plus->destroy(prf_plus);
		return FALSE;
	}
	key_size = crypter_i->get_key_size(crypter_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ei secret %B", &key);
	crypter_i->set_key(crypter_i, key);
	chunk_clear(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_er secret %B", &key);
	crypter_r->set_key(crypter_r, key);
	chunk_clear(&key);
	
	if (this->initiator)
	{
		this->crypter_in = crypter_r;
		this->crypter_out = crypter_i;
	}
	else
	{
		this->crypter_in = crypter_i;
		this->crypter_out = crypter_r;
	}
	
	/* SK_pi/SK_pr used for authentication => stored for later */	
	key_size = this->prf->get_key_size(this->prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_pi secret %B", &key);
	if (this->initiator)
	{
		this->skp_build = key;
	}
	else
	{
		this->skp_verify = key;
	}
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_pr secret %B", &key);
	if (this->initiator)
	{
		this->skp_verify = key;
	}
	else
	{
		this->skp_build = key;
	}
	
	/* all done, prf_plus not needed anymore */
	prf_plus->destroy(prf_plus);
	
	/* save selected proposal */
	this->proposal = proposal->clone(proposal);
	
	return TRUE;
}

/**
 * Implementation of keymat_t.get_proposal
 */
static proposal_t* get_proposal(private_keymat_t *this)
{
	return this->proposal;
}

/**
 * Implementation of keymat_t.get_signer
 */
static signer_t* get_signer(private_keymat_t *this, bool in)
{
	return in ? this->signer_in : this->signer_out;
}

/**
 * Implementation of keymat_t.get_crypter
 */
static crypter_t* get_crypter(private_keymat_t *this, bool in)
{
	return in ? this->crypter_in : this->crypter_out;
}

/**
 * Implementation of keymat_t.get_child_prf
 */
static prf_t* get_child_prf(private_keymat_t *this)
{
	return this->child_prf;
}

/**
 * Implementation of keymat_t.get_auth_octets
 */
static chunk_t get_auth_octets(private_keymat_t *this, bool verify,
							   chunk_t ike_sa_init, chunk_t nonce,
							   identification_t *id)
{
	chunk_t chunk, idx, octets;
	chunk_t skp;
	
	skp = verify ? this->skp_verify : this->skp_build;
	
	chunk = chunk_alloca(4);
	memset(chunk.ptr, 0, chunk.len);
	chunk.ptr[0] = id->get_type(id);
	idx = chunk_cata("cc", chunk, id->get_encoding(id));
	
	DBG3(DBG_IKE, "IDx' %B", &idx);
	DBG3(DBG_IKE, "SK_p %B", &skp);
	this->prf->set_key(this->prf, skp);
	this->prf->allocate_bytes(this->prf, idx, &chunk);
	
	octets = chunk_cat("ccm", ike_sa_init, nonce, chunk);
	DBG3(DBG_IKE, "octets = message + nonce + prf(Sk_px, IDx') %B", &octets);
	return octets;
}

/**
 * Key pad for the AUTH method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
#define IKEV2_KEY_PAD "Key Pad for IKEv2"
#define IKEV2_KEY_PAD_LENGTH 17

/**
 * Implementation of keymat_t.get_psk_sig
 */
static chunk_t get_psk_sig(private_keymat_t *this, bool verify, 
						   chunk_t ike_sa_init, chunk_t nonce, chunk_t secret,
						   identification_t *id)
{
	chunk_t key_pad, key, sig, octets;
	
	if (!secret.len)
	{	/* EAP uses SK_p if no MSK has been established */
		secret = verify ? this->skp_verify : this->skp_build;
	}
	octets = get_auth_octets(this, verify, ike_sa_init, nonce, id);
	/* AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>) */
	key_pad = chunk_create(IKEV2_KEY_PAD, IKEV2_KEY_PAD_LENGTH);
	this->prf->set_key(this->prf, secret);
	this->prf->allocate_bytes(this->prf, key_pad, &key);
	this->prf->set_key(this->prf, key);
	this->prf->allocate_bytes(this->prf, octets, &sig);
	DBG4(DBG_IKE, "secret %B", &secret);
	DBG4(DBG_IKE, "prf(secret, keypad) %B", &key);
	DBG3(DBG_IKE, "AUTH = prf(prf(secret, keypad), octets) %B", &sig);
	chunk_free(&octets);
	chunk_free(&key);
	
	return sig;
}

/**
 * Implementation of keymat_t.destroy.
 */
static void destroy(private_keymat_t *this)
{
	DESTROY_IF(this->dh);
	DESTROY_IF(this->signer_in);
	DESTROY_IF(this->signer_out);
	DESTROY_IF(this->crypter_in);
	DESTROY_IF(this->crypter_out);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->child_prf);
	DESTROY_IF(this->proposal);
	chunk_clear(&this->skp_verify);
	chunk_clear(&this->skp_build);
	free(this);
}

/**
 * See header
 */
keymat_t *keymat_create(bool initiator)
{
	private_keymat_t *this = malloc_thing(private_keymat_t);
	
	this->public.set_dh_group = (bool(*)(keymat_t*, diffie_hellman_group_t group))set_dh_group;
	this->public.get_dh = (diffie_hellman_t*(*)(keymat_t*))get_dh;
	this->public.derive_keys = (bool(*)(keymat_t*, proposal_t *proposal, chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id, keymat_t *rekey))derive_keys;
	this->public.get_proposal = (proposal_t*(*)(keymat_t*))get_proposal;
	this->public.get_signer = (signer_t*(*)(keymat_t*, bool in))get_signer;
	this->public.get_crypter = (crypter_t*(*)(keymat_t*, bool in))get_crypter;
	this->public.get_child_prf = (prf_t*(*)(keymat_t*))get_child_prf;
	this->public.get_auth_octets = (chunk_t(*)(keymat_t *, bool verify, chunk_t ike_sa_init, chunk_t nonce, identification_t *id))get_auth_octets;
	this->public.get_psk_sig = (chunk_t(*)(keymat_t*, bool verify, chunk_t ike_sa_init, chunk_t nonce, chunk_t secret, identification_t *id))get_psk_sig;
	this->public.destroy = (void(*)(keymat_t*))destroy;
	
	this->initiator = initiator;
	
	this->dh = NULL;
	this->signer_in = NULL;
	this->signer_out = NULL;
	this->crypter_in = NULL;
	this->crypter_out = NULL;
	this->prf = NULL;
	this->child_prf = NULL;
	this->proposal = NULL;
	this->skp_verify = chunk_empty;
	this->skp_build = chunk_empty;
	
	return &this->public;
}

