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

#include "ha_sync_dispatcher.h"

#include <daemon.h>
#include <processing/jobs/callback_job.h>

typedef struct private_ha_sync_dispatcher_t private_ha_sync_dispatcher_t;

/**
 * Private data of an ha_sync_dispatcher_t object.
 */
struct private_ha_sync_dispatcher_t {

	/**
	 * Public ha_sync_dispatcher_t interface.
	 */
	ha_sync_dispatcher_t public;

	/**
	 * socket to pull messages from
	 */
	ha_sync_socket_t *socket;

	/**
	 * Synced SA state cache
	 */
	ha_sync_cache_t *cache;

	/**
	 * Dispatcher job
	 */
	callback_job_t *job;
};

/**
 * Quick and dirty hack implementation of diffie_hellman_t.get_shared_secret
 */
static status_t get_shared_secret(diffie_hellman_t *this, chunk_t *secret)
{
	*secret = chunk_clone((*(chunk_t*)this->destroy));
	return SUCCESS;
}

/**
 * Process messages of type IKE_ADD
 */
static void process_ike_add(private_ha_sync_dispatcher_t *this,
							ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa = NULL;
	u_int16_t encr = 0, len = 0, integ = 0, prf = 0;
	chunk_t nonce_i = chunk_empty, nonce_r = chunk_empty, secret = chunk_empty;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = this->cache->get_ike_sa(this->cache, value.ike_sa_id);
				break;
			case HA_SYNC_IKE_REKEY_ID:
				DBG1(DBG_IKE, "TODO: rekey HA sync");
				break;
			case HA_SYNC_NONCE_I:
				nonce_i = value.chunk;
				break;
			case HA_SYNC_NONCE_R:
				nonce_r = value.chunk;
				break;
			case HA_SYNC_SECRET:
				secret = value.chunk;
				break;
			case HA_SYNC_ALG_ENCR:
				encr = value.u16;
				break;
			case HA_SYNC_ALG_ENCR_LEN:
				len = value.u16;
				break;
			case HA_SYNC_ALG_INTEG:
				integ = value.u16;
				break;
			case HA_SYNC_ALG_PRF:
				prf = value.u16;
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);


	if (ike_sa)
	{
		proposal_t *proposal;
		keymat_t *keymat;
		/* quick and dirty hack of a DH implementation ;-) */
		diffie_hellman_t dh = { .get_shared_secret = get_shared_secret,
								.destroy = (void*)&secret };

		proposal = proposal_create(PROTO_IKE);
		keymat = ike_sa->get_keymat(ike_sa);
		if (integ)
		{
			proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, integ, 0);
		}
		if (encr)
		{
			proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, encr, len);
		}
		if (prf)
		{
			proposal->add_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, prf, 0);
		}
		if (!keymat->derive_ike_keys(keymat, proposal, &dh, nonce_i, nonce_r,
									ike_sa->get_id(ike_sa), NULL))
		{
			DBG1(DBG_IKE, "HA sync keymat derivation failed");
		}
		proposal->destroy(proposal);
	}
}

/**
 * Apply a condition flag to the IKE_SA if it is in set
 */
static void set_condition(ike_sa_t *ike_sa, ike_condition_t set,
						  ike_condition_t flag)
{
	ike_sa->set_condition(ike_sa, flag, flag & set);
}

/**
 * Apply a extension flag to the IKE_SA if it is in set
 */
static void set_extension(ike_sa_t *ike_sa, ike_extension_t set,
						  ike_extension_t flag)
{
	if (flag & set)
	{
		ike_sa->enable_extension(ike_sa, flag);
	}
}

/**
 * Process messages of type IKE_UPDATE
 */
static void process_ike_update(private_ha_sync_dispatcher_t *this,
							   ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa = NULL;
	peer_cfg_t *peer_cfg = NULL;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		if (attribute != HA_SYNC_IKE_ID && ike_sa == NULL)
		{
			DBG1(DBG_IKE, "HA_SYNC_IKE_ID must be first attribute");
			break;
		}
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = this->cache->get_ike_sa(this->cache, value.ike_sa_id);
				break;
			case HA_SYNC_LOCAL_ID:
				ike_sa->set_my_id(ike_sa, value.id->clone(value.id));
				break;
			case HA_SYNC_REMOTE_ID:
				ike_sa->set_other_id(ike_sa, value.id->clone(value.id));
				break;
			case HA_SYNC_EAP_ID:
				ike_sa->set_eap_identity(ike_sa, value.id->clone(value.id));
				break;
			case HA_SYNC_LOCAL_ADDR:
				ike_sa->set_my_host(ike_sa, value.host->clone(value.host));
				break;
			case HA_SYNC_REMOTE_ADDR:
				ike_sa->set_other_host(ike_sa, value.host->clone(value.host));
				break;
			case HA_SYNC_LOCAL_VIP:
			case HA_SYNC_REMOTE_VIP:
				ike_sa->set_virtual_ip(ike_sa, attribute == HA_SYNC_LOCAL_VIP,
									   value.host->clone(value.host));
				break;
			case HA_SYNC_ADDITIONAL_ADDR:
				ike_sa->add_additional_address(ike_sa,
											   value.host->clone(value.host));
				break;
			case HA_SYNC_CONFIG_NAME:
				peer_cfg = charon->backends->get_peer_cfg_by_name(
												charon->backends, value.str);
				break;
			case HA_SYNC_CONDITIONS:
				set_condition(ike_sa, value.u32, EXT_NATT);
				set_condition(ike_sa, value.u32, EXT_MOBIKE);
				set_condition(ike_sa, value.u32, EXT_HASH_AND_URL);
				break;
			case HA_SYNC_EXTENSIONS:
				set_extension(ike_sa, value.u32, COND_NAT_ANY);
				set_extension(ike_sa, value.u32, COND_NAT_HERE);
				set_extension(ike_sa, value.u32, COND_NAT_THERE);
				set_extension(ike_sa, value.u32, COND_NAT_FAKE);
				set_extension(ike_sa, value.u32, COND_EAP_AUTHENTICATED);
				set_extension(ike_sa, value.u32, COND_CERTREQ_SEEN);
				set_extension(ike_sa, value.u32, COND_ORIGINAL_INITIATOR);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (peer_cfg)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
		peer_cfg->destroy(peer_cfg);
	}
	else
	{
		DBG1(DBG_IKE, "HA sync is missing nodes configuration");
	}
}

/**
 * Process messages of type IKE_DELETE
 */
static void process_ike_delete(private_ha_sync_dispatcher_t *this,
							   ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				this->cache->delete_ike_sa(this->cache, value.ike_sa_id);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Process messages of type CHILD_ADD
 */
static void process_child_add(private_ha_sync_dispatcher_t *this,
							  ha_sync_message_t *message)
{
	chunk_t chunk = message->get_encoding(message);

	DBG1(DBG_CHD, "CHILD_ADD: %B", &chunk);
}

/**
 * Process messages of type CHILD_DELETE
 */
static void process_child_delete(private_ha_sync_dispatcher_t *this,
								 ha_sync_message_t *message)
{
	chunk_t chunk = message->get_encoding(message);

	DBG1(DBG_CHD, "CHILD_DELETE: %B", &chunk);
}

/**
 * Dispatcher job function
 */
static job_requeue_t dispatch(private_ha_sync_dispatcher_t *this)
{
	ha_sync_message_t *message;

	message = this->socket->pull(this->socket);
	switch (message->get_type(message))
	{
		case HA_SYNC_IKE_ADD:
			process_ike_add(this, message);
			break;
		case HA_SYNC_IKE_UPDATE:
			process_ike_update(this, message);
			break;
		case HA_SYNC_IKE_DELETE:
			process_ike_delete(this, message);
			break;
		case HA_SYNC_IKE_REKEY:
			break;
		case HA_SYNC_CHILD_ADD:
			process_child_add(this, message);
			break;
		case HA_SYNC_CHILD_DELETE:
			process_child_delete(this, message);
			break;
		default:
			DBG1(DBG_CFG, "received unknown HA sync message type %d",
				 message->get_type(message));
			break;
	}
	message->destroy(message);

	return JOB_REQUEUE_DIRECT;
}

/**
 * Implementation of ha_sync_dispatcher_t.destroy.
 */
static void destroy(private_ha_sync_dispatcher_t *this)
{
	this->job->cancel(this->job);
	free(this);
}

/**
 * See header
 */
ha_sync_dispatcher_t *ha_sync_dispatcher_create(ha_sync_socket_t *socket,
												ha_sync_cache_t *cache)
{
	private_ha_sync_dispatcher_t *this = malloc_thing(private_ha_sync_dispatcher_t);

	this->public.destroy = (void(*)(ha_sync_dispatcher_t*))destroy;

	this->socket = socket;
	this->cache = cache;
	this->job = callback_job_create((callback_job_cb_t)dispatch,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}
