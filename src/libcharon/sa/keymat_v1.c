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

	/**
	 * Crypter wrapped in an aead_t interface
	 */
	aead_t *aead;

	/**
	 * Key used for authentication during main mode
	 */
	chunk_t skeyid;

	/**
	 * Key to derive key material from for non-ISAKMP SAs, rekeying
	 */
	chunk_t skeyid_d;

	/**
	 * Key used for authentication after main mode
	 */
	chunk_t skeyid_a;
};

/**
 * Constants used in key derivation.
 */
static const chunk_t octet_0 = chunk_from_chars(0x00);
static const chunk_t octet_1 = chunk_from_chars(0x01);
static const chunk_t octet_2 = chunk_from_chars(0x02);

/**
 * Simple aead_t implementation without support for authentication.
 */
typedef struct {
	/** implements aead_t interface */
	aead_t aead;
	/** crypter to be used */
	crypter_t *crypter;
} private_aead_t;


METHOD(aead_t, encrypt, void,
	private_aead_t *this, chunk_t plain, chunk_t assoc, chunk_t iv,
	chunk_t *encrypted)
{
	this->crypter->encrypt(this->crypter, plain, iv, encrypted);
}

METHOD(aead_t, decrypt, bool,
	private_aead_t *this, chunk_t encrypted, chunk_t assoc, chunk_t iv,
	chunk_t *plain)
{
	this->crypter->decrypt(this->crypter, encrypted, iv, plain);
	return TRUE;
}

METHOD(aead_t, get_block_size, size_t,
	private_aead_t *this)
{
	return this->crypter->get_block_size(this->crypter);
}

METHOD(aead_t, get_icv_size, size_t,
	private_aead_t *this)
{
	return 0;
}

METHOD(aead_t, get_iv_size, size_t,
	private_aead_t *this)
{
	/* in order to create the messages properly we return 0 here */
	return 0;
}

METHOD(aead_t, get_key_size, size_t,
	private_aead_t *this)
{
	return this->crypter->get_key_size(this->crypter);
}

METHOD(aead_t, set_key, void,
	private_aead_t *this, chunk_t key)
{
	this->crypter->set_key(this->crypter, key);
}

METHOD(aead_t, aead_destroy, void,
	private_aead_t *this)
{
	this->crypter->destroy(this->crypter);
	free(this);
}

/**
 * Expand SKEYID_e according to Appendix B in RFC 2409.
 * TODO-IKEv1: verify keys (e.g. for weak keys, see Appendix B)
 */
static chunk_t expand_skeyid_e(chunk_t skeyid_e, size_t key_size, prf_t *prf)
{
	size_t block_size;
	chunk_t seed, ka;
	int i;

	if (skeyid_e.len >= key_size)
	{	/* no expansion required, reduce to key_size */
		skeyid_e.len = key_size;
		return skeyid_e;
	}
	block_size = prf->get_block_size(prf);
	ka = chunk_alloc((key_size / block_size + 1) * block_size);
	ka.len = key_size;

	/* Ka = K1 | K2 | ..., K1 = prf(SKEYID_e, 0), K2 = prf(SKEYID_e, K1) ... */
	prf->set_key(prf, skeyid_e);
	seed = octet_0;
	for (i = 0; i < key_size; i += block_size)
	{
		prf->get_bytes(prf, seed, ka.ptr + i);
		seed = chunk_create(ka.ptr + i, block_size);
	}
	chunk_clear(&skeyid_e);
	return ka;
}

/**
 * Create a simple implementation of the aead_t interface which only encrypts
 * or decrypts data.
 */
static aead_t *create_aead(proposal_t *proposal, prf_t *prf, chunk_t skeyid_e)
{
	private_aead_t *this;
	u_int16_t alg, key_size;
	crypter_t *crypter;
	chunk_t ka;

	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg,
								 &key_size))
	{
		DBG1(DBG_IKE, "no %N selected",
			 transform_type_names, ENCRYPTION_ALGORITHM);
		return NULL;
	}
	crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size / 8);
	if (!crypter)
	{
		DBG1(DBG_IKE, "%N %N (key size %d) not supported!",
			 transform_type_names, ENCRYPTION_ALGORITHM,
			 encryption_algorithm_names, alg, key_size);
		return NULL;
	}
	key_size = crypter->get_key_size(crypter);
	ka = expand_skeyid_e(skeyid_e, crypter->get_key_size(crypter), prf);
	DBG4(DBG_IKE, "encryption key Ka %B", &ka);
	crypter->set_key(crypter, ka);
	chunk_clear(&ka);

	INIT(this,
		.aead = {
			.encrypt = _encrypt,
			.decrypt = _decrypt,
			.get_block_size = _get_block_size,
			.get_icv_size = _get_icv_size,
			.get_iv_size = _get_iv_size,
			.get_key_size = _get_key_size,
			.set_key = _set_key,
			.destroy = _aead_destroy,
		},
		.crypter = crypter,
	);
	return &this->aead;
}

/**
 * Converts integrity algorithm to PRF algorithm
 */
static u_int16_t auth_to_prf(u_int16_t alg)
{
	switch (alg)
	{
		case AUTH_HMAC_SHA1_96:
			return PRF_HMAC_SHA1;
		case AUTH_HMAC_SHA2_256_128:
			return PRF_HMAC_SHA2_256;
		case AUTH_HMAC_SHA2_384_192:
			return PRF_HMAC_SHA2_384;
		case AUTH_HMAC_SHA2_512_256:
			return PRF_HMAC_SHA2_512;
		case AUTH_HMAC_MD5_96:
			return PRF_HMAC_MD5;
		case AUTH_AES_XCBC_96:
			return PRF_AES128_XCBC;
		default:
			return PRF_UNDEFINED;
	}
}

/**
 * Adjust the key length for PRF algorithms that expect a fixed key length.
 */
static void adjust_keylen(u_int16_t alg, chunk_t *key)
{
	switch (alg)
	{
		case PRF_AES128_XCBC:
			/* while rfc4434 defines variable keys for AES-XCBC, rfc3664 does
				 * not and therefore fixed key semantics apply to XCBC for key
				 * derivation. */
			key->len = min(key->len, 16);
			break;
		default:
			/* all other algorithms use variable key length */
			break;
	}
}

METHOD(keymat_v1_t, derive_ike_keys, bool,
	private_keymat_v1_t *this, proposal_t *proposal, diffie_hellman_t *dh,
	chunk_t dh_other, chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id,
	auth_class_t auth, shared_key_t *shared_key)
{
	chunk_t g_xy, g_xi, g_xr, dh_me, spi_i, spi_r, nonces, data, skeyid_e;
	u_int16_t alg;

	spi_i = chunk_alloca(sizeof(u_int64_t));
	spi_r = chunk_alloca(sizeof(u_int64_t));

	if (!proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{	/* no PRF negotiated, use HMAC version of integrity algorithm instead */
		if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL)
			|| (alg = auth_to_prf(alg)) == PRF_UNDEFINED)
		{
			DBG1(DBG_IKE, "no %N selected",
				 transform_type_names, PSEUDO_RANDOM_FUNCTION);
			return FALSE;
		}
	}
	this->prf_alg = alg;
	this->prf = lib->crypto->create_prf(lib->crypto, alg);
	if (!this->prf)
	{
		DBG1(DBG_IKE, "%N %N not supported!",
			 transform_type_names, PSEUDO_RANDOM_FUNCTION,
			 pseudo_random_function_names, alg);
		return FALSE;
	}
	if (this->prf->get_block_size(this->prf) <
		this->prf->get_key_size(this->prf))
	{	/* TODO-IKEv1: support PRF output expansion (RFC 2409, Appendix B) */
		DBG1(DBG_IKE, "expansion of %N %N output not supported!",
			 transform_type_names, PSEUDO_RANDOM_FUNCTION,
			 pseudo_random_function_names, alg);
		return FALSE;
	}

	if (dh->get_shared_secret(dh, &g_xy) != SUCCESS)
	{
		return FALSE;
	}
	DBG4(DBG_IKE, "shared Diffie Hellman secret %B", &g_xy);

	*((u_int64_t*)spi_i.ptr) = id->get_initiator_spi(id);
	*((u_int64_t*)spi_r.ptr) = id->get_responder_spi(id);
	nonces = chunk_cata("cc", nonce_i, nonce_r);

	switch (auth)
	{
		case AUTH_CLASS_PSK:
		{	/* SKEYID = prf(pre-shared-key, Ni_b | Nr_b) */
			chunk_t psk;
			if (!shared_key)
			{
				chunk_clear(&g_xy);
				return FALSE;
			}
			psk = shared_key->get_key(shared_key);
			adjust_keylen(alg, &psk);
			this->prf->set_key(this->prf, psk);
			this->prf->allocate_bytes(this->prf, nonces, &this->skeyid);
			break;
		}
		case AUTH_CLASS_PUBKEY:
		{
			/* signatures : SKEYID = prf(Ni_b | Nr_b, g^xy)
			 * pubkey encr: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R) */
			/* TODO-IKEv1: implement key derivation for other schemes,
			 * fall for now */
		}
		default:
			/* authentication class not supported */
			chunk_clear(&g_xy);
			return FALSE;
	}
	adjust_keylen(alg, &this->skeyid);
	DBG4(DBG_IKE, "SKEYID %B", &this->skeyid);

	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	data = chunk_cat("cccc", g_xy, spi_i, spi_r, octet_0);
	this->prf->set_key(this->prf, this->skeyid);
	this->prf->allocate_bytes(this->prf, data, &this->skeyid_d);
	chunk_clear(&data);
	DBG4(DBG_IKE, "SKEYID_d %B", &this->skeyid_d);

	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	data = chunk_cat("ccccc", this->skeyid_d, g_xy, spi_i, spi_r, octet_1);
	this->prf->set_key(this->prf, this->skeyid);
	this->prf->allocate_bytes(this->prf, data, &this->skeyid_a);
	chunk_clear(&data);
	DBG4(DBG_IKE, "SKEYID_a %B", &this->skeyid_a);

	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	data = chunk_cat("ccccc", this->skeyid_a, g_xy, spi_i, spi_r, octet_2);
	this->prf->set_key(this->prf, this->skeyid);
	this->prf->allocate_bytes(this->prf, data, &skeyid_e);
	chunk_clear(&data);
	DBG4(DBG_IKE, "SKEYID_e %B", &skeyid_e);

	chunk_clear(&g_xy);

	this->aead = create_aead(proposal, this->prf, skeyid_e);
	if (!this->aead)
	{
		return FALSE;
	}

	return TRUE;
}

METHOD(keymat_t, create_dh, diffie_hellman_t*,
	private_keymat_v1_t *this, diffie_hellman_group_t group)
{
	return lib->crypto->create_dh(lib->crypto, group);
}

METHOD(keymat_t, get_aead, aead_t*,
	private_keymat_v1_t *this, bool in)
{
	return this->aead;
}

METHOD(keymat_t, destroy, void,
	private_keymat_v1_t *this)
{
	DESTROY_IF(this->prf);
	DESTROY_IF(this->aead);
	chunk_clear(&this->skeyid);
	chunk_clear(&this->skeyid_d);
	chunk_clear(&this->skeyid_a);
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
				.get_aead = _get_aead,
				.destroy = _destroy,
			},
			.derive_ike_keys = _derive_ike_keys,
		},
		.initiator = initiator,
		.prf_alg = PRF_UNDEFINED,
	);

	return &this->public;
}
