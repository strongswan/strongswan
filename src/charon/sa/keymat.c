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
	 * Negotiated PRF algorithm
	 */
	pseudo_random_function_t prf_alg;
	
	/**
	 * Key to derive key material from for CHILD_SAs, rekeying
	 */
	chunk_t skd;
	
	/**
	 * Key to build outging authentication data (SKp)
	 */
	chunk_t skp_build;

	/**
	 * Key to verify incoming authentication data (SKp)
	 */
	chunk_t skp_verify;
};

typedef struct keylen_entry_t keylen_entry_t;

/**
 * Implicit key length for an algorithm
 */
struct keylen_entry_t {
	/** IKEv2 algorithm identifier */
	int algo;
	/** key length in bits */
	int len;
};

#define END_OF_LIST -1

/**
 * Keylen for encryption algos
 */
keylen_entry_t keylen_enc[] = {
	{ENCR_DES, 					 64},
	{ENCR_3DES, 				192},
	{END_OF_LIST,				  0}
};

/**
 * Keylen for integrity algos
 */
keylen_entry_t keylen_int[] = {
	{AUTH_HMAC_MD5_96, 			128},
	{AUTH_HMAC_SHA1_96,			160},
	{AUTH_HMAC_SHA2_256_128,	256},
	{AUTH_HMAC_SHA2_384_192,	384},
	{AUTH_HMAC_SHA2_512_256,	512},
	{AUTH_AES_XCBC_96,			128},
	{END_OF_LIST,				  0}
};

/**
 * Lookup key length of an algorithm
 */
static int lookup_keylen(keylen_entry_t *list, int algo)
{
	while (list->algo != END_OF_LIST)
	{
		if (algo == list->algo)
		{
			return list->len;
		}
		list++;
	}
	return 0;
}

/**
 * Implementation of keymat_t.create_dh
 */
static diffie_hellman_t* create_dh(private_keymat_t *this,
								   diffie_hellman_group_t group)
{
	return lib->crypto->create_dh(lib->crypto, group);;
}

/**
 * Implementation of keymat_t.derive_keys
 */
static bool derive_ike_keys(private_keymat_t *this, proposal_t *proposal,
							diffie_hellman_t *dh, chunk_t nonce_i,
							chunk_t nonce_r, ike_sa_id_t *id,
							pseudo_random_function_t rekey_function,
							chunk_t rekey_skd)
{
	chunk_t skeyseed, key, secret, full_nonce, fixed_nonce, prf_plus_seed;
	chunk_t spi_i, spi_r;
	crypter_t *crypter_i, *crypter_r;
	signer_t *signer_i, *signer_r;
	prf_plus_t *prf_plus;
	u_int16_t alg, key_size;
	prf_t *rekey_prf = NULL;
	
	spi_i = chunk_alloca(sizeof(u_int64_t));
	spi_r = chunk_alloca(sizeof(u_int64_t));
	
	if (dh->get_shared_secret(dh, &secret) != SUCCESS)
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
	this->prf_alg = alg;
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
			key_size = this->prf->get_key_size(this->prf)/2;
			nonce_i.len = min(nonce_i.len, key_size);
			nonce_r.len = min(nonce_r.len, key_size);
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
	if (rekey_function == PRF_UNDEFINED) /* not rekeying */
	{
		/* SKEYSEED = prf(Ni | Nr, g^ir) */
		this->prf->set_key(this->prf, fixed_nonce);
		this->prf->allocate_bytes(this->prf, secret, &skeyseed);
		this->prf->set_key(this->prf, skeyseed);
		prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	}
	else
	{
		/* SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr) 
		 * use OLD SAs PRF functions for both prf_plus and prf */
		rekey_prf = lib->crypto->create_prf(lib->crypto, rekey_function);
		if (!rekey_prf)
		{
			DBG1(DBG_IKE, "PRF of old SA %N not supported!",
				 pseudo_random_function_names, rekey_function);
			chunk_free(&full_nonce);
			chunk_free(&fixed_nonce);
			chunk_clear(&prf_plus_seed);
			return FALSE;
		}
		secret = chunk_cat("mc", secret, full_nonce);
		rekey_prf->set_key(rekey_prf, rekey_skd);
		rekey_prf->allocate_bytes(rekey_prf, secret, &skeyseed);
		rekey_prf->set_key(rekey_prf, skeyseed);
		prf_plus = prf_plus_create(rekey_prf, prf_plus_seed);
	}
	DBG4(DBG_IKE, "SKEYSEED %B", &skeyseed);
	
	chunk_clear(&skeyseed);
	chunk_clear(&secret);
	chunk_free(&full_nonce);
	chunk_free(&fixed_nonce);
	chunk_clear(&prf_plus_seed);
	
	/* KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr */
	
	/* SK_d is used for generating CHILD_SA key mat => store for later use */
	key_size = this->prf->get_key_size(this->prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &this->skd);
	DBG4(DBG_IKE, "Sk_d secret %B", &this->skd);
	
	/* SK_ai/SK_ar used for integrity protection => signer_in/signer_out */
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		DBG1(DBG_IKE, "no %N selected",
			 transform_type_names, INTEGRITY_ALGORITHM);
		prf_plus->destroy(prf_plus);
		DESTROY_IF(rekey_prf);
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
		DESTROY_IF(rekey_prf);
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
		DESTROY_IF(rekey_prf);
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
		DESTROY_IF(rekey_prf);
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
	DESTROY_IF(rekey_prf);
	
	return TRUE;
}

/**
 * Implementation of keymat_t.derive_child_keys
 */
static bool derive_child_keys(private_keymat_t *this,
							  proposal_t *proposal, diffie_hellman_t *dh,
							  chunk_t nonce_i, chunk_t nonce_r,
							  chunk_t *encr_i, chunk_t *integ_i,
							  chunk_t *encr_r, chunk_t *integ_r)
{
	u_int16_t enc_alg, int_alg, enc_size = 0, int_size = 0;
	chunk_t seed, secret = chunk_empty;
	prf_plus_t *prf_plus;
	
	if (dh)
	{
		if (dh->get_shared_secret(dh, &secret) != SUCCESS)
		{
			return FALSE;
		}
		DBG4(DBG_CHD, "DH secret %B", &secret);
	}
	seed = chunk_cata("mcc", secret, nonce_i, nonce_r);
	DBG4(DBG_CHD, "seed %B", &seed);
	
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM,
								&enc_alg, &enc_size))
	{
		DBG2(DBG_CHD, "  using %N for encryption", 
			 encryption_algorithm_names, enc_alg);
		
		if (!enc_size)
		{
			enc_size = lookup_keylen(keylen_enc, enc_alg);
		}
		if (enc_alg != ENCR_NULL && !enc_size)
		{
			DBG1(DBG_CHD, "no keylength defined for %N",
				 encryption_algorithm_names, enc_alg);
			return FALSE;
		}
		/* to bytes */
		enc_size /= 8;
		
		/* CCM/GCM/CTR needs additional bytes */
		switch (enc_alg)
		{
			case ENCR_AES_CCM_ICV8:
			case ENCR_AES_CCM_ICV12:
			case ENCR_AES_CCM_ICV16:
				enc_size += 3;
				break;
			case ENCR_AES_GCM_ICV8:
			case ENCR_AES_GCM_ICV12:
			case ENCR_AES_GCM_ICV16:
			case ENCR_AES_CTR:
				enc_size += 4;
				break;
			default:
				break;
		}
	}
	
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM,
								&int_alg, &int_size))
	{
		DBG2(DBG_CHD, "  using %N for integrity",
			 integrity_algorithm_names, int_alg);
		
		if (!int_size)
		{
			int_size = lookup_keylen(keylen_int, int_alg);
		}
		if (!int_size)
		{
			DBG1(DBG_CHD, "no keylength defined for %N",
				 integrity_algorithm_names, int_alg);
			return FALSE;
		}
		/* to bytes */
		int_size /= 8;
	}
	
	this->prf->set_key(this->prf, this->skd);
	prf_plus = prf_plus_create(this->prf, seed);
	
	prf_plus->allocate_bytes(prf_plus, enc_size, encr_i);
	prf_plus->allocate_bytes(prf_plus, int_size, integ_i);
	prf_plus->allocate_bytes(prf_plus, enc_size, encr_r);
	prf_plus->allocate_bytes(prf_plus, int_size, integ_r);
	
	prf_plus->destroy(prf_plus);
	
	if (enc_size)
	{
		DBG4(DBG_CHD, "encryption initiator key %B", encr_i);
		DBG4(DBG_CHD, "encryption responder key %B", encr_r);
	}
	if (int_size)
	{
		DBG4(DBG_CHD, "integrity initiator key %B", integ_i);
		DBG4(DBG_CHD, "integrity responder key %B", integ_r);
	}
	return TRUE;
}

/**
 * Implementation of keymat_t.get_skd
 */
static pseudo_random_function_t get_skd(private_keymat_t *this, chunk_t *skd)
{
	*skd = this->skd;
	return this->prf_alg;
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
	DESTROY_IF(this->signer_in);
	DESTROY_IF(this->signer_out);
	DESTROY_IF(this->crypter_in);
	DESTROY_IF(this->crypter_out);
	DESTROY_IF(this->prf);
	chunk_clear(&this->skd);
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
	
	this->public.create_dh = (diffie_hellman_t*(*)(keymat_t*, diffie_hellman_group_t group))create_dh;
	this->public.derive_ike_keys = (bool(*)(keymat_t*, proposal_t *proposal, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r, ike_sa_id_t *id, pseudo_random_function_t,chunk_t))derive_ike_keys;
	this->public.derive_child_keys = (bool(*)(keymat_t*, proposal_t *proposal, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r, chunk_t *encr_i, chunk_t *integ_i, chunk_t *encr_r, chunk_t *integ_r))derive_child_keys;
	this->public.get_skd = (pseudo_random_function_t(*)(keymat_t*, chunk_t *skd))get_skd;
	this->public.get_signer = (signer_t*(*)(keymat_t*, bool in))get_signer;
	this->public.get_crypter = (crypter_t*(*)(keymat_t*, bool in))get_crypter;
	this->public.get_auth_octets = (chunk_t(*)(keymat_t *, bool verify, chunk_t ike_sa_init, chunk_t nonce, identification_t *id))get_auth_octets;
	this->public.get_psk_sig = (chunk_t(*)(keymat_t*, bool verify, chunk_t ike_sa_init, chunk_t nonce, chunk_t secret, identification_t *id))get_psk_sig;
	this->public.destroy = (void(*)(keymat_t*))destroy;
	
	this->initiator = initiator;
	
	this->signer_in = NULL;
	this->signer_out = NULL;
	this->crypter_in = NULL;
	this->crypter_out = NULL;
	this->prf = NULL;
	this->prf_alg = PRF_UNDEFINED;
	this->skd = chunk_empty;
	this->skp_verify = chunk_empty;
	this->skp_build = chunk_empty;
	
	return &this->public;
}

