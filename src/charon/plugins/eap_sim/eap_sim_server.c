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
#include <simaka_crypto.h>

/* number of triplets for one authentication */
#define TRIPLET_COUNT 3

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
	 * EAP-SIM/AKA crypto helper
	 */
	simaka_crypto_t *crypto;

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

	/**
	 * EAP-SIM message we have initiated
	 */
	simaka_subtype_t pending;
};

/* version of SIM protocol we speak */
static chunk_t version = chunk_from_chars(0x00,0x01);

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

	if (this->pending != SIM_START)
	{
		DBG1(DBG_IKE, "received %N, but not expected",
			 simaka_subtype_names, SIM_START);
		return FAILED;
	}

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
				if (!simaka_attribute_skippable(type))
				{
					enumerator->destroy(enumerator);
					return FAILED;
				}
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
	rand = rands = chunk_alloca(SIM_RAND_LEN * TRIPLET_COUNT);
	kc = kcs = chunk_alloca(SIM_KC_LEN * TRIPLET_COUNT);
	sres = sreses = chunk_alloca(SIM_SRES_LEN * TRIPLET_COUNT);
	rands.len = kcs.len = sreses.len = 0;
	for (i = 0; i < TRIPLET_COUNT; i++)
	{
		if (!get_provider_triplet(this, rand.ptr, sres.ptr, kc.ptr))
		{
			DBG1(DBG_IKE, "getting EAP-SIM triplet %d failed", i);
			return FAILED;
		}
		rands.len += SIM_RAND_LEN;
		sreses.len += SIM_SRES_LEN;
		kcs.len += SIM_KC_LEN;
		rand = chunk_skip(rand, SIM_RAND_LEN);
		sres = chunk_skip(sres, SIM_SRES_LEN);
		kc = chunk_skip(kc, SIM_KC_LEN);
	}
	free(this->sreses.ptr);
	this->sreses = chunk_clone(sreses);

	data = chunk_cata("cccc", kcs, nonce, version, version);
	free(this->msk.ptr);
	this->msk = this->crypto->derive_keys_full(this->crypto, this->peer, data);

	/* build response with AT_MAC, built over "EAP packet | NONCE_MT" */
	message = simaka_message_create(TRUE, this->identifier++, EAP_SIM,
									SIM_CHALLENGE, this->crypto);
	message->add_attribute(message, AT_RAND, rands);
	*out = message->generate(message, nonce);
	message->destroy(message);

	this->pending = SIM_CHALLENGE;
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

	if (this->pending != SIM_CHALLENGE)
	{
		DBG1(DBG_IKE, "received %N, but not expected",
			 simaka_subtype_names, SIM_CHALLENGE);
		return FAILED;
	}

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (!simaka_attribute_skippable(type))
		{
			enumerator->destroy(enumerator);
			return FAILED;
		}
	}
	enumerator->destroy(enumerator);

	/* verify AT_MAC attribute, signature is over "EAP packet | n*SRES"  */
	if (!in->verify(in, this->sreses))
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
									 simaka_message_t *in)
{
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data;

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == AT_CLIENT_ERROR_CODE)
		{
			u_int16_t code;

			memcpy(&code, data.ptr, sizeof(code));
			DBG1(DBG_IKE, "received EAP-SIM client error '%N'",
				 simaka_client_error_names, ntohs(code));
		}
		else if (!simaka_attribute_skippable(type))
		{
			break;
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

	message = simaka_message_create_from_payload(in, this->crypto);
	if (!message)
	{
		return FAILED;
	}
	if (!message->parse(message))
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
			status = process_client_error(this, message);
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

	message = simaka_message_create(TRUE, this->identifier++, EAP_SIM,
									SIM_START, this->crypto);
	message->add_attribute(message, AT_VERSION_LIST, version);
	*out = message->generate(message, chunk_empty);
	message->destroy(message);

	this->pending = SIM_START;
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
	this->crypto->destroy(this->crypto);
	this->peer->destroy(this->peer);
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

	this->public.interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate;
	this->public.interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process;
	this->public.interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.interface.destroy = (void(*)(eap_method_t*))destroy;

	this->crypto = simaka_crypto_create();
	if (!this->crypto)
	{
		free(this);
		return NULL;
	}
	this->peer = peer->clone(peer);
	this->sreses = chunk_empty;
	this->msk = chunk_empty;
	this->pending = 0;
	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

