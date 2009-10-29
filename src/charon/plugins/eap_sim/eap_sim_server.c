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

/** length of the AT_NONCE_S value */
#define NONCE_LEN 16

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
	identification_t *permanent;

	/**
	 * pseudonym ID of peer
	 */
	identification_t *pseudonym;

	/**
	 * reauthentication ID of peer
	 */
	identification_t *reauth;

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
	 * Nonce value used in AT_NONCE_S
	 */
	chunk_t nonce;

	/**
	 * Counter value negotiated, network order
	 */
	chunk_t counter;

	/**
	 * MSK, used for EAP-SIM based IKEv2 authentication
	 */
	chunk_t msk;

	/**
	 * Do we request fast reauthentication?
	 */
	bool use_reauth;

	/**
	 * Do we request pseudonym identities?
	 */
	bool use_pseudonym;

	/**
	 * Do we request permanent identities?
	 */
	bool use_permanent;

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
static bool get_triplet(private_eap_sim_server_t *this, identification_t *peer,
						char *rand, char *sres, char *kc)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	int tried = 0;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_triplet(provider, peer, rand, sres, kc))
		{
			enumerator->destroy(enumerator);
			return TRUE;
		}
		tried++;
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE, "tried %d SIM providers, but none had a triplet for '%Y'",
		 tried, peer);
	return FALSE;
}

/**
 * Generate a new reauthentication identity for next fast reauthentication
 */
static identification_t* gen_reauth(private_eap_sim_server_t *this,
									char mk[HASH_SIZE_SHA1])
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *reauth = NULL;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		reauth = provider->gen_reauth(provider, this->permanent, mk);
		if (reauth)
		{
			DBG1(DBG_IKE, "proposing new reauthentication identity '%Y'", reauth);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return reauth;
}

/**
 * Check if an identity is a known reauthentication identity
 */
static identification_t* is_reauth(private_eap_sim_server_t *this,
								identification_t *id, char mk[HASH_SIZE_SHA1],
								u_int16_t *counter)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *permanent = NULL;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		permanent = provider->is_reauth(provider, id, mk, counter);
		if (permanent)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return permanent;
}

/**
 * Generate a new pseudonym for next authentication
 */
static identification_t* gen_pseudonym(private_eap_sim_server_t *this)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *pseudonym = NULL;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		pseudonym = provider->gen_pseudonym(provider, this->permanent);
		if (pseudonym)
		{
			DBG1(DBG_IKE, "proposing new pseudonym '%Y'", pseudonym);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return pseudonym;
}

/**
 * Check if an identity is a known pseudonym
 */
static identification_t* is_pseudonym(private_eap_sim_server_t *this,
									  identification_t *pseudonym)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	identification_t *permanent = NULL;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		permanent = provider->is_pseudonym(provider, pseudonym);
		if (permanent)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return permanent;
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
	if (this->use_reauth)
	{
		message->add_attribute(message, AT_ANY_ID_REQ, chunk_empty);
	}
	else if (this->use_pseudonym)
	{
		message->add_attribute(message, AT_FULLAUTH_ID_REQ, chunk_empty);
	}
	else if (this->use_permanent)
	{
		message->add_attribute(message, AT_PERMANENT_ID_REQ, chunk_empty);
	}
	*out = message->generate(message, chunk_empty);
	message->destroy(message);

	this->pending = SIM_START;
	return NEED_MORE;
}

/**
 * Initiate  EAP-SIM/Request/Re-authentication message
 */
static status_t reauthenticate(private_eap_sim_server_t *this,
							   char mk[HASH_SIZE_SHA1], u_int16_t counter,
							   eap_payload_t **out)
{
	simaka_message_t *message;
	identification_t *next;
	chunk_t mkc;
	rng_t *rng;

	DBG1(DBG_IKE, "initiating EAP-SIM reauthentication");

	rng = this->crypto->get_rng(this->crypto);
	rng->allocate_bytes(rng, NONCE_LEN, &this->nonce);

	mkc = chunk_create(mk, HASH_SIZE_SHA1);
	counter = htons(counter);
	this->counter = chunk_clone(chunk_create((char*)&counter, sizeof(counter)));

	this->crypto->derive_keys_reauth(this->crypto, mkc);
	this->msk = this->crypto->derive_keys_reauth_msk(this->crypto,
								this->reauth, this->counter, this->nonce, mkc);

	message = simaka_message_create(TRUE, this->identifier++, EAP_SIM,
									SIM_REAUTHENTICATION, this->crypto);
	message->add_attribute(message, AT_COUNTER, this->counter);
	message->add_attribute(message, AT_NONCE_S, this->nonce);
	next = gen_reauth(this, mk);
	if (next)
	{
		message->add_attribute(message, AT_NEXT_REAUTH_ID,
							   next->get_encoding(next));
		next->destroy(next);
	}
	/* create AT_MAC over EAP-Message|NONCE_S */
	*out = message->generate(message, this->nonce);
	message->destroy(message);

	this->pending = SIM_REAUTHENTICATION;
	return NEED_MORE;
}

/**
 * process an EAP-SIM/Response/Reauthentication message
 */
static status_t process_reauthentication(private_eap_sim_server_t *this,
									simaka_message_t *in, eap_payload_t **out)
{
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data, counter = chunk_empty;
	bool too_small = FALSE;

	if (this->pending != SIM_REAUTHENTICATION)
	{
		DBG1(DBG_IKE, "received %N, but not expected",
			 simaka_subtype_names, SIM_REAUTHENTICATION);
		return FAILED;
	}

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_COUNTER:
				counter = data;
				break;
			case AT_COUNTER_TOO_SMALL:
				too_small = TRUE;
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

	/* verify AT_MAC attribute, signature is over "EAP packet | NONCE_S"  */
	if (!in->verify(in, this->nonce))
	{
		return FAILED;
	}
	if (too_small)
	{
		DBG1(DBG_IKE, "received %N, initiating full authentication",
			 simaka_attribute_names, AT_COUNTER_TOO_SMALL);
		this->use_reauth = FALSE;
		this->crypto->clear_keys(this->crypto);
		return initiate(this, out);
	}
	if (!chunk_equals(counter, this->counter))
	{
		DBG1(DBG_IKE, "received counter does not match");
		return FAILED;
	}
	return SUCCESS;
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
	chunk_t data, identity = chunk_empty, nonce = chunk_empty, mk;
	chunk_t rands, rand, kcs, kc, sreses, sres;
	bool supported = FALSE;
	identification_t *id;
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
			case AT_IDENTITY:
				identity = data;
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

	if (identity.len)
	{
		identification_t *permanent;
		char buf[identity.len + 1];

		snprintf(buf, sizeof(buf), "%.*s", identity.len, identity.ptr);
		id = identification_create_from_string(buf);

		if (this->use_reauth && !nonce.len)
		{
			char mk[HASH_SIZE_SHA1];
			u_int16_t counter;

			permanent = is_reauth(this, id, mk, &counter);
			if (permanent)
			{
				DBG1(DBG_IKE, "received reauthentication identity '%Y' "
					 "mapping to '%Y'",  id, permanent);
				this->permanent->destroy(this->permanent);
				this->permanent = permanent;
				this->reauth = id;
				return reauthenticate(this, mk, counter, out);
			}
			DBG1(DBG_IKE, "received unknown reauthentication identity '%Y', "
				 "initiating full authentication", id);
			this->use_reauth = FALSE;
			id->destroy(id);
			return initiate(this, out);
		}
		if (this->use_pseudonym)
		{
			permanent = is_pseudonym(this, id);
			if (permanent)
			{
				DBG1(DBG_IKE, "received pseudonym identity '%Y' "
					 "mapping to '%Y'", id, permanent);
				this->permanent->destroy(this->permanent);
				this->permanent = permanent;
				this->pseudonym = id->clone(id);
				/* we already have a new permanent identity now */
				this->use_permanent = FALSE;
			}
		}
		if (!this->pseudonym && this->use_permanent)
		{
			DBG1(DBG_IKE, "received %spermanent identity '%Y'",
				 this->use_pseudonym ? "pseudonym or " : "", id);
			this->permanent->destroy(this->permanent);
			this->permanent = id->clone(id);
		}
		id->destroy(id);
	}

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
		if (!get_triplet(this, this->permanent, rand.ptr, sres.ptr, kc.ptr))
		{
			if (this->use_pseudonym)
			{
				/* probably received a pseudonym we couldn't map */
				DBG1(DBG_IKE, "failed to map pseudonym identity '%Y', "
					 "fallback to permanent identity request", this->permanent);
				this->use_pseudonym = FALSE;
				DESTROY_IF(this->pseudonym);
				this->pseudonym = NULL;
				return initiate(this, out);
			}
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
	id = this->permanent;
	if (this->pseudonym)
	{
		id = this->pseudonym;
	}
	this->msk = this->crypto->derive_keys_full(this->crypto, id, data, &mk);

	/* build response with AT_MAC, built over "EAP packet | NONCE_MT" */
	message = simaka_message_create(TRUE, this->identifier++, EAP_SIM,
									SIM_CHALLENGE, this->crypto);
	message->add_attribute(message, AT_RAND, rands);
	id = gen_reauth(this, mk.ptr);
	if (id)
	{
		message->add_attribute(message, AT_NEXT_REAUTH_ID,
							   id->get_encoding(id));
		id->destroy(id);
	}
	else
	{
		id = gen_pseudonym(this);
		if (id)
		{
			message->add_attribute(message, AT_NEXT_PSEUDONYM,
								   id->get_encoding(id));
			id->destroy(id);
		}
	}
	*out = message->generate(message, nonce);
	message->destroy(message);

	free(mk.ptr);
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
		case SIM_REAUTHENTICATION:
			status = process_reauthentication(this, message, out);
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
	this->permanent->destroy(this->permanent);
	DESTROY_IF(this->pseudonym);
	DESTROY_IF(this->reauth);
	free(this->sreses.ptr);
	free(this->nonce.ptr);
	free(this->msk.ptr);
	free(this->counter.ptr);
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
	this->permanent = peer->clone(peer);
	this->pseudonym = NULL;
	this->reauth = NULL;
	this->sreses = chunk_empty;
	this->nonce = chunk_empty;
	this->msk = chunk_empty;
	this->counter = chunk_empty;
	this->pending = 0;
	this->use_reauth = this->use_pseudonym = this->use_permanent =
		lib->settings->get_bool(lib->settings,
								"charon.plugins.eap-sim.request_identity", TRUE);

	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

