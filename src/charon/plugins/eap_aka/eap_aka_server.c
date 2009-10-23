/*
 * Copyright (C) 2006-2009 Martin Willi
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

#include "eap_aka_server.h"

#include <daemon.h>
#include <library.h>

#include <simaka_message.h>
#include <simaka_crypto.h>

typedef struct private_eap_aka_server_t private_eap_aka_server_t;

/**
 * Private data of an eap_aka_server_t object.
 */
struct private_eap_aka_server_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_aka_server_t public;

	/**
	 * EAP-AKA crypto helper
	 */
	simaka_crypto_t *crypto;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP identifier value
	 */
	u_int8_t identifier;

	/**
	 * MSK
	 */
	chunk_t msk;

	/**
	 * Expected Result XRES
	 */
	chunk_t xres;

	/**
	 * Random value RAND
	 */
	chunk_t rand;

	/**
	 * EAP-AKA message we have initiated
	 */
	simaka_subtype_t pending;

	/**
	 * Did the client send a synchronize request?
	 */
	bool synchronized;
};

/**
 * Check if an unknown attribute is skippable
 */
static bool attribute_skippable(simaka_attribute_t attribute)
{
	if (attribute >= 0 && attribute <= 127)
	{
		DBG1(DBG_IKE, "ignoring skippable attribute %N",
			 simaka_attribute_names, attribute);
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of eap_method_t.initiate
 */
static status_t initiate(private_eap_aka_server_t *this, eap_payload_t **out)
{
	simaka_message_t *message;
	enumerator_t *enumerator;
	sim_provider_t *provider;
	char rand[AKA_RAND_LEN], xres[AKA_RES_LEN];
	char ck[AKA_CK_LEN], ik[AKA_IK_LEN], autn[AKA_AUTN_LEN];
	chunk_t data;
	bool found = FALSE;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_quintuplet(provider, this->peer,
									 rand, xres, ck, ik, autn))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		DBG1(DBG_IKE, "no AKA provider found with quintuplets for '%Y'",
			 this->peer);
		return FAILED;
	}

	data = chunk_cata("cc", chunk_create(ik, AKA_IK_LEN),
					  chunk_create(ck, AKA_CK_LEN));
	free(this->msk.ptr);
	this->msk = this->crypto->derive_keys_full(this->crypto, this->peer, data);
	this->rand = chunk_clone(chunk_create(rand, AKA_RAND_LEN));
	this->xres = chunk_clone(chunk_create(xres, AKA_RES_LEN));

	message = simaka_message_create(TRUE, this->identifier++, EAP_AKA,
									AKA_CHALLENGE, this->crypto);
	message->add_attribute(message, AT_RAND, this->rand);
	message->add_attribute(message, AT_AUTN, chunk_create(autn, AKA_AUTN_LEN));
	*out = message->generate(message, chunk_empty);
	message->destroy(message);

	this->pending = AKA_CHALLENGE;
	return NEED_MORE;
}

/**
 * Process EAP-AKA/Response/Challenge message
 */
static status_t process_challenge(private_eap_aka_server_t *this,
								  simaka_message_t *in)
{
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data, res = chunk_empty;

	if (this->pending != AKA_CHALLENGE)
	{
		DBG1(DBG_IKE, "received %N, but not expected",
			 simaka_subtype_names, AKA_CHALLENGE);
		return FAILED;
	}
	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_RES:
				res = data;
				break;
			default:
				if (!attribute_skippable(type))
				{
					enumerator->destroy(enumerator);
					DBG1(DBG_IKE, "found non skippable attribute %N",
						 simaka_attribute_names, type);
					return FAILED;
				}
				break;
		}
	}
	enumerator->destroy(enumerator);

	/* verify MAC of EAP message, AT_MAC */
	if (!in->verify(in, chunk_empty))
	{
		DBG1(DBG_IKE, "AT_MAC verification failed");
		return FAILED;
	}
	/* compare received RES against stored XRES */
	if (!chunk_equals(res, this->xres))
	{
		DBG1(DBG_IKE, "received RES does not match XRES");
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Process EAP-AKA/Response/SynchronizationFailure message
 */
static status_t process_synchronize(private_eap_aka_server_t *this,
									simaka_message_t *in, eap_payload_t **out)
{
	sim_provider_t *provider;
	enumerator_t *enumerator;
	simaka_attribute_t type;
	chunk_t data, auts = chunk_empty;
	bool found = FALSE;

	if (this->synchronized)
	{
		DBG1(DBG_IKE, "received %N, but peer did already resynchronize",
			 simaka_subtype_names, AKA_SYNCHRONIZATION_FAILURE);
		return FAILED;
	}

	DBG1(DBG_IKE, "received synchronization request, retrying...");

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case AT_AUTS:
				auts = data;
				break;
			default:
				if (!attribute_skippable(type))
				{
					enumerator->destroy(enumerator);
					DBG1(DBG_IKE, "found non skippable attribute %N",
						 simaka_attribute_names, type);
					return FAILED;
				}
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!auts.len)
	{
		DBG1(DBG_IKE, "synchronization request didn't contain usable AUTS");
		return FAILED;
	}

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->resync(provider, this->peer, this->rand.ptr, auts.ptr))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		DBG1(DBG_IKE, "no AKA provider found supporting "
			 "resynchronization for '%Y'", this->peer);
		return FAILED;
	}
	this->synchronized = TRUE;
	return initiate(this, out);
}

/**
 * Process EAP-AKA/Response/ClientErrorCode message
 */
static status_t process_client_error(private_eap_aka_server_t *this,
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
			DBG1(DBG_IKE, "received EAP-AKA client error '%N'",
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
 * Process EAP-AKA/Response/AuthenticationReject message
 */
static status_t process_authentication_reject(private_eap_aka_server_t *this,
											  simaka_message_t *in)
{
	DBG1(DBG_IKE, "received %N, authentication failed",
		 simaka_subtype_names, in->get_subtype(in));
	return FAILED;
}

/**
 * Implementation of eap_method_t.process
 */
static status_t process(private_eap_aka_server_t *this,
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
		case AKA_CHALLENGE:
			status = process_challenge(this, message);
			break;
		case AKA_SYNCHRONIZATION_FAILURE:
			status = process_synchronize(this, message, out);
			break;
		case AKA_CLIENT_ERROR:
			status = process_client_error(this, message);
			break;
		case AKA_AUTHENTICATION_REJECT:
			status = process_authentication_reject(this, message);
			break;
		default:
			DBG1(DBG_IKE, "unable to process EAP-AKA subtype %N",
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
static eap_type_t get_type(private_eap_aka_server_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_AKA;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_aka_server_t *this, chunk_t *msk)
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
static bool is_mutual(private_eap_aka_server_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_aka_server_t *this)
{
	this->crypto->destroy(this->crypto);
	this->peer->destroy(this->peer);
	free(this->msk.ptr);
	free(this->xres.ptr);
	free(this->rand.ptr);
	free(this);
}

/*
 * Described in header.
 */
eap_aka_server_t *eap_aka_server_create(identification_t *server,
										identification_t *peer)
{
	private_eap_aka_server_t *this = malloc_thing(private_eap_aka_server_t);

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
	this->msk = chunk_empty;
	this->xres = chunk_empty;
	this->rand = chunk_empty;
	this->pending = 0;
	this->synchronized = FALSE;
	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

