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

#include "eap_sim_peer.h"

#include <daemon.h>

#include <simaka_message.h>

/* number of tries we do authenticate */
#define MAX_TRIES 3

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

typedef struct private_eap_sim_peer_t private_eap_sim_peer_t;

/**
 * Private data of an eap_sim_peer_t object.
 */
struct private_eap_sim_peer_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_sim_peer_t public;

	/**
	 * permanent ID of peer
	 */
	identification_t *peer;

	/**
	 * RNG to create nonces, IVs
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
	 * how many times we try to authenticate
	 */
	int tries;

	/**
	 * version list received from server
	 */
	chunk_t version_list;

	/**
	 * Nonce value used in AT_NONCE_MT/AT_NONCE_S
	 */
	chunk_t nonce;

	/**
	 * MSK, used for EAP-SIM based IKEv2 authentication
	 */
	chunk_t msk;
};

/* version of SIM protocol we speak */
static chunk_t version = chunk_from_chars(0x00,0x01);
/* client error codes used in AT_CLIENT_ERROR_CODE */
static chunk_t client_error_general = chunk_from_chars(0x00, 0x01);
static chunk_t client_error_unsupported = chunk_from_chars(0x00, 0x02);
static chunk_t client_error_insufficient = chunk_from_chars(0x00, 0x03);

/**
 * Read a triplet from the SIM card
 */
static bool get_card_triplet(private_eap_sim_peer_t *this,
							 char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	sim_card_t *card;
	bool success = FALSE;

	enumerator = charon->sim->create_card_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &card))
	{
		if (card->get_triplet(card, this->peer, rand, sres, kc))
		{
			success = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!success)
	{
		DBG1(DBG_IKE, "no SIM card found with triplets for '%Y'", this->peer);
	}
	return success;
}

/**
 * Derive EAP keys from kc when using full authentication
 */
static void derive_keys_full(private_eap_sim_peer_t *this, chunk_t kcs)
{
	char mk[HASH_SIZE_SHA1], k_encr[KENCR_LEN], k_auth[KAUTH_LEN];
	chunk_t tmp;
	int i;

	/* MK = SHA1(Identity|n*Kc|NONCE_MT|Version List|Selected Version) */
	tmp = chunk_cata("ccccc", this->peer->get_encoding(this->peer),
					 kcs, this->nonce, this->version_list, version);
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
 * Send a SIM_CLIENT_ERROR
 */
static eap_payload_t* create_client_error(private_eap_sim_peer_t *this,
										  u_int8_t identifier, chunk_t code)
{
	simaka_message_t *message;
	eap_payload_t *out;

	message = simaka_message_create(FALSE, identifier,
									EAP_SIM, SIM_CLIENT_ERROR);
	message->add_attribute(message, AT_CLIENT_ERROR_CODE, code);
	out = message->generate(message, NULL, NULL, NULL, chunk_empty);
	message->destroy(message);
	return out;
}

/**
 * process an EAP-SIM/Request/Start message
 */
static status_t process_start(private_eap_sim_peer_t *this,
							  simaka_message_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data;
	bool supported = FALSE;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_VERSION_LIST:
			{
				free(this->version_list.ptr);
				this->version_list = chunk_clone(data);
				while (data.len >= version.len)
				{
					if (memeq(data.ptr, version.ptr, version.len))
					{
						supported = TRUE;
						break;
					}
				}
				break;
			}
			default:
				DBG1(DBG_IKE, "ignoring EAP-SIM attribute %N",
					 simaka_attribute_names, type);
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!supported)
	{
		DBG1(DBG_IKE, "server does not support EAP-SIM version number 1");
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_unsupported);
		return NEED_MORE;
	}

	/* generate AT_NONCE_MT value */
	free(this->nonce.ptr);
	this->rng->allocate_bytes(this->rng, NONCE_LEN, &this->nonce);

	message = simaka_message_create(FALSE, in->get_identifier(in),
									EAP_SIM, SIM_START);
	message->add_attribute(message, AT_SELECTED_VERSION, version);
	message->add_attribute(message, AT_NONCE_MT, this->nonce);
	*out = message->generate(message, NULL, NULL, NULL, chunk_empty);
	message->destroy(message);

	return NEED_MORE;
}

/**
 * process an EAP-SIM/Request/Challenge message
 */
static status_t process_challenge(private_eap_sim_peer_t *this,
								  simaka_message_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data, rands = chunk_empty, kcs, kc, sreses, sres;

	if (this->tries-- <= 0)
	{
		/* give up without notification. This hack is required as some buggy
		 * server implementations won't respect our client-error. */
		return FAILED;
	}

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_RAND:
			{
				rands = data;
				break;
			}
			default:
				DBG1(DBG_IKE, "ignoring EAP-SIM attribute %N",
					 simaka_attribute_names, type);
				break;
		}
	}
	enumerator->destroy(enumerator);

	/* excepting two or three RAND, each 16 bytes. We require two valid
	 * and different RANDs */
	if ((rands.len != 2 * RAND_LEN && rands.len != 3 * RAND_LEN) ||
		memeq(rands.ptr, rands.ptr + RAND_LEN, RAND_LEN))
	{
		DBG1(DBG_IKE, "no valid AT_RAND received");
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_insufficient);
		return NEED_MORE;
	}
	/* get two or three KCs/SRESes from SIM using RANDs */
	kcs = kc = chunk_alloca(rands.len / 2);
	sreses = sres = chunk_alloca(rands.len / 4);
	while (rands.len >= RAND_LEN)
	{
		if (!get_card_triplet(this, rands.ptr, sres.ptr, kc.ptr))
		{
			DBG1(DBG_IKE, "unable to get EAP-SIM triplet");
			*out = create_client_error(this, in->get_identifier(in),
									   client_error_general);
			return NEED_MORE;
		}
		DBG3(DBG_IKE, "got triplet for RAND %b\n  Kc %b\n  SRES %b",
			 rands.ptr, RAND_LEN, sres.ptr, SRES_LEN, kc.ptr, KC_LEN);
		kc = chunk_skip(kc, KC_LEN);
		sres = chunk_skip(sres, SRES_LEN);
		rands = chunk_skip(rands, RAND_LEN);
	}

	derive_keys_full(this, kcs);

	/* verify AT_MAC attribute, signature is over "EAP packet | NONCE_MT"  */
	if (!in->verify(in, this->signer, this->nonce))
	{
		DBG1(DBG_IKE, "AT_MAC verification failed");
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_general);
		return NEED_MORE;
	}

	/* build response with AT_MAC, built over "EAP packet | n*SRES" */
	message = simaka_message_create(FALSE, in->get_identifier(in),
									EAP_SIM, SIM_CHALLENGE);
	*out = message->generate(message, NULL, NULL, this->signer, sreses);
	message->destroy(message);
	return NEED_MORE;
}

/**
 * process an EAP-SIM/Request/Notification message
 */
static status_t process_notification(private_eap_sim_peer_t *this,
									 simaka_message_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data;
	bool success = TRUE;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == AT_NOTIFICATION)
		{
			/* test success bit */
			if (!(data.ptr[0] & 0x80))
			{
				success = FALSE;
				DBG1(DBG_IKE, "received EAP-SIM notification error %#B", &data);
			}
			else
			{
				DBG1(DBG_IKE, "received EAP-SIM notification code %#B", &data);
			}
		}
	}
	enumerator->destroy(enumerator);

	if (success)
	{	/* empty notification reply */
		message = simaka_message_create(FALSE, in->get_identifier(in),
										EAP_SIM, SIM_NOTIFICATION);
		*out = message->generate(message, NULL, NULL, NULL, chunk_empty);
		message->destroy(message);
	}
	else
	{
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_general);
	}
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process
 */
static status_t process(private_eap_sim_peer_t *this,
						eap_payload_t *in, eap_payload_t **out)
{
	simaka_message_t *message;
	status_t status;

	message = simaka_message_create_from_payload(in);
	if (!message)
	{
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_general);
		return NEED_MORE;
	}
	if (!message->parse(message, this->crypter))
	{
		message->destroy(message);
		*out = create_client_error(this, in->get_identifier(in),
								   client_error_general);
		return NEED_MORE;
	}
	switch (message->get_subtype(message))
	{
		case SIM_START:
			status = process_start(this, message, out);
			break;
		case SIM_CHALLENGE:
			status = process_challenge(this, message, out);
			break;
		case SIM_NOTIFICATION:
			status = process_notification(this, message, out);
			break;
		default:
			*out = create_client_error(this, in->get_identifier(in),
									   client_error_general);
			status = NEED_MORE;
			break;
	}
	message->destroy(message);
	return status;
}

/**
 * Implementation of eap_method_t.initiate
 */
static status_t initiate(private_eap_sim_peer_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_sim_peer_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_SIM;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_sim_peer_t *this, chunk_t *msk)
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
static bool is_mutual(private_eap_sim_peer_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_sim_peer_t *this)
{
	this->peer->destroy(this->peer);
	DESTROY_IF(this->rng);
	DESTROY_IF(this->hasher);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->crypter);
	free(this->version_list.ptr);
	free(this->nonce.ptr);
	free(this->msk.ptr);
	free(this);
}

/*
 * Described in header.
 */
eap_sim_peer_t *eap_sim_peer_create(identification_t *server,
									identification_t *peer)
{
	private_eap_sim_peer_t *this = malloc_thing(private_eap_sim_peer_t);

	this->peer = peer->clone(peer);
	this->tries = MAX_TRIES;
	this->version_list = chunk_empty;
	this->nonce = chunk_empty;
	this->msk = chunk_empty;

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

