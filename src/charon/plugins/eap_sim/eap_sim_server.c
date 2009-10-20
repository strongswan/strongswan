/*
 * Copyright (C) 2007-2009 Martin Willi
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

#include "eap_sim_server.h"

#include <daemon.h>

#include <simaka_message.h>

/* number of triplets for one authentication */
#define TRIPLET_COUNT 3

/** length of the AT_NONCE_MT/AT_NONCE_S nonce value */
#define NONCE_LEN 16
/** length of the AT_MAC value */
#define MAC_LEN 16
/** length of the AT_RAND value */
#define RAND_LEN 16
/** length of Kc */
#define KC_LEN 8
/** length of SRES */
#define SRES_LEN 4
/** length of the k_encr key */
#define KENCR_LEN 16
/** length of the k_auth key */
#define KAUTH_LEN 16
/** length of the MSK */
#define MSK_LEN 64
/** length of the EMSK */
#define EMSK_LEN 64

typedef struct private_eap_sim_server_t private_eap_sim_server_t;

/**
 * Private data of an eap_sim_server_t object.
 */
struct private_eap_sim_server_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_sim_server_t public;

	/**
	 * permanent ID of peer
	 */
	identification_t *peer;

	/**
	 * Random number generator for nonce, IVs
	 */
	rng_t *rng;

	/**
	 * hashing function
	 */
	hasher_t *hasher;

	/**
	 * prf
	 */
	prf_t *prf;

	/**
	 * MAC function
	 */
	signer_t *signer;

	/**
	 * encryption function
	 */
	crypter_t *crypter;

	/**
	 * unique EAP identifier
	 */
	u_int8_t identifier;

	/**
	 * concatenated SRES values
	 */
	chunk_t sreses;

	/**
	 * MSK, used for EAP-SIM based IKEv2 authentication
	 */
	chunk_t msk;
};

/**
 * Fetch a triplet from a provider
 */
static bool get_provider_triplet(private_eap_sim_server_t *this,
								 char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	int tried = 0;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_triplet(provider, this->peer, rand, sres, kc))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
		tried++;
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM providers, but none had a triplet for '%Y'",
		 tried, this->peer);
	return FALSE;
}

/**
 * Derive EAP keys from kc when using full authentication
 */
static void derive_keys_full(private_eap_sim_server_t *this,
							 chunk_t kcs, chunk_t nonce)
{
	char mk[HASH_SIZE_SHA1], k_encr[KENCR_LEN], k_auth[KAUTH_LEN];
	chunk_t tmp;
	int i;

	/* MK = SHA1(Identity|n*Kc|NONCE_MT|Version List|Selected Version) */
	tmp = chunk_cata("ccccc", this->peer->get_encoding(this->peer),
					 kcs, nonce, version, version);
	this->hasher->get_hash(this->hasher, tmp, mk);
	DBG3(DBG_IKE, "MK = SHA1(%B\n) = %b", &tmp, mk, HASH_SIZE_SHA1);

	/* K_encr | K_auth | MSK | EMSK = prf() | prf() | prf() | prf()
	 * We currently don't need EMSK, so three prf() are sufficient */
	this->prf->set_key(this->prf, chunk_create(mk, HASH_SIZE_SHA1));
	tmp = chunk_alloca(this->prf->get_block_size(this->prf) * 3);
	for (i = 0; i < 3; i++)
	{
		this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 3 * i);
	}
	memcpy(k_encr, tmp.ptr, KENCR_LEN);
	tmp = chunk_skip(tmp, KENCR_LEN);
	memcpy(k_auth, tmp.ptr, KAUTH_LEN);
	tmp = chunk_skip(tmp, KAUTH_LEN);
	free(this->msk.ptr);
	this->msk = chunk_alloc(MSK_LEN);
	memcpy(this->msk.ptr, tmp.ptr, MSK_LEN);
	DBG3(DBG_IKE, "K_encr %b\nK_auth %b\nMSK %B",
		 k_encr, KENCR_LEN, k_auth, KAUTH_LEN, &this->msk);

	this->signer->set_key(this->signer, chunk_create(k_auth, KAUTH_LEN));
	this->crypter->set_key(this->crypter, chunk_create(k_encr, KENCR_LEN));
}

/**
 * process an EAP-SIM/Response/Start message
 */
static status_t process_start(private_eap_sim_server_t *this,
							  simaka_message_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data, rands, rand, kcs, kc, sreses, sres, nonce = chunk_empty;
	bool supported = FALSE;
	int i;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_NONCE_MT:
				nonce = data;
				break;
			case AT_SELECTED_VERSION:
				if (chunk_equals(data, version))
				{
					supported = TRUE;
				}
				break;
			default:
				DBG1(DBG_IKE, "ignoring EAP-SIM attribute %N",
					 simaka_attribute_names, type);
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!supported || !nonce.len)
	{
		DBG1(DBG_IKE, "received incomplete EAP-SIM/Response/Start");
		return FAILED;
	}

	/* read triplets from provider */
	rand = rands = chunk_alloca(RAND_LEN * TRIPLET_COUNT);
	kc = kcs = chunk_alloca(KC_LEN * TRIPLET_COUNT);
	sres = sreses = chunk_alloca(SRES_LEN * TRIPLET_COUNT);
	rands.len = kcs.len = sreses.len = 0;
	for (i = 0; i < TRIPLET_COUNT; i++)
	{
		if (!get_provider_triplet(this, rand.ptr, sres.ptr, kc.ptr))
		{
			DBG1(DBG_IKE, "getting EAP-SIM triplet %d failed", i);
			return FAILED;
		}
		rands.len += RAND_LEN;
		sreses.len += SRES_LEN;
		kcs.len += KC_LEN;
		rand = chunk_skip(rand, RAND_LEN);
		sres = chunk_skip(sres, SRES_LEN);
		kc = chunk_skip(kc, KC_LEN);
	}
	free(this->sreses.ptr);
	this->sreses = chunk_clone(sreses);

	derive_keys_full(this, kcs, nonce);

	/* build response with AT_MAC, built over "EAP packet | NONCE_MT" */
	message = simaka_message_create(TRUE, this->identifier++,
									EAP_SIM, SIM_CHALLENGE);
	message->add_attribute(message, AT_RAND, rands);
	*out = message->generate(message, NULL, NULL, this->signer, nonce);
	message->destroy(message);
	return NEED_MORE;
}

/**
 * process an EAP-SIM/Response/Challenge message
 */
static status_t process_challenge(private_eap_sim_server_t *this,
								  simaka_message_t *in, eap_payload_t **out)
{
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		DBG1(DBG_IKE, "ignoring EAP-SIM attribute %N",
			 simaka_attribute_names, type);
	}
	enumerator->destroy(enumerator);

	/* verify AT_MAC attribute, signature is over "EAP packet | n*SRES"  */
	if (!in->verify(in, this->signer, this->sreses))
	{
		DBG1(DBG_IKE, "AT_MAC verification failed");
		return FAILED;
	}
	return SUCCESS;
}

/**
 * EAP-SIM/Response/ClientErrorCode message
 */
static status_t process_client_error(private_eap_sim_server_t *this,
									 simaka_message_t *in, eap_payload_t **out)
{
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == AT_CLIENT_ERROR_CODE)
		{
			DBG1(DBG_IKE, "received EAP-SIM client error code %#B", &data);
		}
		else
		{
			DBG1(DBG_IKE, "ignoring EAP-SIM attribute %N",
				 simaka_attribute_names, type);
		}
	}
	enumerator->destroy(enumerator);
	return FAILED;
}

/**
 * Implementation of eap_method_t.process
 */
static status_t process(private_eap_sim_server_t *this,
						eap_payload_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	status_t status;

	message = simaka_message_create_from_payload(in);
	if (!message)
	{
		return FAILED;
	}
	if (!message->parse(message, this->crypter))
	{
		message->destroy(message);
		return FAILED;
	}
	switch (message->get_subtype(message))
	{
		case SIM_START:
			status = process_start(this, message, out);
			break;
		case SIM_CHALLENGE:
			status = process_challenge(this, message, out);
			break;
		case SIM_CLIENT_ERROR:
			status = process_client_error(this, message, out);
			break;
		default:
			DBG1(DBG_IKE, "unable to process EAP-SIM subtype %N",
				 simaka_subtype_names, message->get_subtype(message));
			status = FAILED;
			break;
	}
	message->destroy(message);
	return status;
}

/**
 * Implementation of eap_method_t.initiate
 */
static status_t initiate(private_eap_sim_server_t *this, eap_payload_t **out)
{
	simaka_message_t *message;

	message = simaka_message_create(TRUE, this->identifier++,
									EAP_SIM, SIM_START);
	message->add_attribute(message, AT_VERSION_LIST, version);
	*out = message->generate(message, NULL, NULL, NULL, chunk_empty);
	message->destroy(message);
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_sim_server_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_SIM;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_sim_server_t *this, chunk_t *msk)
{
	if (this->msk.ptr)
	{
		*msk = this->msk;
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_sim_server_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_sim_server_t *this)
{
	this->peer->destroy(this->peer);
	DESTROY_IF(this->rng);
	DESTROY_IF(this->hasher);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->crypter);
	free(this->sreses.ptr);
	free(this->msk.ptr);
	free(this);
}

/*
 * Described in header.
 */
eap_sim_server_t *eap_sim_server_create(identification_t *server,
										identification_t *peer)
{
	private_eap_sim_server_t *this = malloc_thing(private_eap_sim_server_t);

	this->peer = peer->clone(peer);
	this->sreses = chunk_empty;
	this->msk = chunk_empty;
	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	this->public.interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate;
	this->public.interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process;
	this->public.interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.interface.destroy = (void(*)(eap_method_t*))destroy;

	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	this->prf = lib->crypto->create_prf(lib->crypto, PRF_FIPS_SHA1_160);
	this->signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_128);
	this->crypter = lib->crypto->create_crypter(lib->crypto, ENCR_AES_CBC, 16);
	if (!this->rng || !this->hasher || !this->prf ||
		!this->signer || !this->crypter)
	{
		DBG1(DBG_IKE, "unable to use EAP-SIM, missing algorithms");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

