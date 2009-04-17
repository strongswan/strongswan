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
	ike_sa_t *ike_sa = NULL, *old_sa = NULL;
	u_int16_t encr = 0, len = 0, integ = 0, prf = 0, old_prf = PRF_UNDEFINED;
	chunk_t nonce_i = chunk_empty, nonce_r = chunk_empty;
	chunk_t secret = chunk_empty, old_skd = chunk_empty;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = ike_sa_create(value.ike_sa_id);
				break;
			case HA_SYNC_IKE_REKEY_ID:
				old_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														  value.ike_sa_id);
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
			case HA_SYNC_OLD_SKD:
				old_skd = value.chunk;
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
			case HA_SYNC_ALG_OLD_PRF:
				old_prf = value.u16;
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
		charon->bus->set_sa(charon->bus, ike_sa);
		if (keymat->derive_ike_keys(keymat, proposal, &dh, nonce_i, nonce_r,
									 ike_sa->get_id(ike_sa), old_prf, old_skd))
		{
			if (old_sa)
			{
				peer_cfg_t *peer_cfg = old_sa->get_peer_cfg(old_sa);

				if (peer_cfg)
				{
					ike_sa->set_peer_cfg(ike_sa, peer_cfg);
					ike_sa->inherit(ike_sa, old_sa);
				}
				charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, old_sa);
				old_sa = NULL;
			}
			ike_sa->set_state(ike_sa, IKE_CONNECTING);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
		else
		{
			DBG1(DBG_IKE, "HA sync keymat derivation failed");
			ike_sa->destroy(ike_sa);
		}
		charon->bus->set_sa(charon->bus, NULL);
		proposal->destroy(proposal);
	}
	if (old_sa)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, old_sa);
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
			/* must be first attribute */
			break;
		}
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														  value.ike_sa_id);
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
				if (peer_cfg)
				{
					ike_sa->set_peer_cfg(ike_sa, peer_cfg);
					peer_cfg->destroy(peer_cfg);
				}
				else
				{
					DBG1(DBG_IKE, "HA sync is missing nodes peer configuration");
				}
				break;
			case HA_SYNC_EXTENSIONS:
				set_extension(ike_sa, value.u32, EXT_NATT);
				set_extension(ike_sa, value.u32, EXT_MOBIKE);
				set_extension(ike_sa, value.u32, EXT_HASH_AND_URL);
				break;
			case HA_SYNC_CONDITIONS:
				set_condition(ike_sa, value.u32, COND_NAT_ANY);
				set_condition(ike_sa, value.u32, COND_NAT_HERE);
				set_condition(ike_sa, value.u32, COND_NAT_THERE);
				set_condition(ike_sa, value.u32, COND_NAT_FAKE);
				set_condition(ike_sa, value.u32, COND_EAP_AUTHENTICATED);
				set_condition(ike_sa, value.u32, COND_CERTREQ_SEEN);
				set_condition(ike_sa, value.u32, COND_ORIGINAL_INITIATOR);
				break;
			case HA_SYNC_INITIATE_MID:
				ike_sa->set_message_id(ike_sa, TRUE, value.u32);
				break;
			case HA_SYNC_RESPOND_MID:
				ike_sa->set_message_id(ike_sa, FALSE, value.u32);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (ike_sa)
	{
		if (ike_sa->get_state(ike_sa) == IKE_CONNECTING &&
			ike_sa->get_peer_cfg(ike_sa))
		{
			ike_sa->set_state(ike_sa, IKE_PASSIVE);
		}
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
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
	ike_sa_t *ike_sa;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = charon->ike_sa_manager->checkout(
									charon->ike_sa_manager, value.ike_sa_id);
				if (ike_sa)
				{
					charon->ike_sa_manager->checkin_and_destroy(
									charon->ike_sa_manager, ike_sa);
				}
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Lookup a child cfg from the peer cfg by name
 */
static child_cfg_t* find_child_cfg(ike_sa_t *ike_sa, char *name)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	peer_cfg = ike_sa->get_peer_cfg(ike_sa);
	if (peer_cfg)
	{
		enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (streq(current->get_name(current), name))
			{
				found = current;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return found;
}

/**
 * Process messages of type CHILD_ADD
 */
static void process_child_add(private_ha_sync_dispatcher_t *this,
							  ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa = NULL;
	char *config_name;
	child_cfg_t *config = NULL;
	child_sa_t *child_sa;
	proposal_t *proposal;
	keymat_t *keymat;
	bool initiator, failed = FALSE;
	u_int32_t inbound_spi = 0, outbound_spi = 0;
	u_int16_t inbound_cpi = 0, outbound_cpi = 0;
	u_int8_t mode = MODE_TUNNEL, ipcomp = 0;
	u_int16_t encr = ENCR_UNDEFINED, integ = AUTH_UNDEFINED, len = 0;
	chunk_t nonce_i = chunk_empty, nonce_r = chunk_empty, secret = chunk_empty;
	chunk_t encr_i, integ_i, encr_r, integ_r;
	linked_list_t *local_ts, *remote_ts;
	/* quick and dirty hack of a DH implementation */
	diffie_hellman_t dh = { .get_shared_secret = get_shared_secret,
							.destroy = (void*)&secret };

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														  value.ike_sa_id);
				initiator = value.ike_sa_id->is_initiator(value.ike_sa_id);
				break;
			case HA_SYNC_CONFIG_NAME:
				config_name = value.str;
				break;
			case HA_SYNC_INBOUND_SPI:
				inbound_spi = value.u32;
				break;
			case HA_SYNC_OUTBOUND_SPI:
				outbound_spi = value.u32;
				break;
			case HA_SYNC_INBOUND_CPI:
				inbound_cpi = value.u32;
				break;
			case HA_SYNC_OUTBOUND_CPI:
				outbound_cpi = value.u32;
				break;
			case HA_SYNC_IPSEC_MODE:
				mode = value.u8;
				break;
			case HA_SYNC_IPCOMP:
				ipcomp = value.u8;
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
			case HA_SYNC_NONCE_I:
				nonce_i = value.chunk;
				break;
			case HA_SYNC_NONCE_R:
				nonce_r = value.chunk;
				break;
			case HA_SYNC_SECRET:
				secret = value.chunk;
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!ike_sa)
	{
		DBG1(DBG_CHD, "IKE_SA for HA sync CHILD_SA not found");
		return;
	}
	config = find_child_cfg(ike_sa, config_name);
	if (!config)
	{
		DBG1(DBG_CHD, "HA sync is missing nodes child configuration");
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return;
	}

	child_sa = child_sa_create(ike_sa->get_my_host(ike_sa),
							   ike_sa->get_other_host(ike_sa), config, 0,
							   ike_sa->has_condition(ike_sa, COND_NAT_ANY));
	child_sa->set_mode(child_sa, mode);
	child_sa->set_protocol(child_sa, PROTO_ESP);
	child_sa->set_ipcomp(child_sa, ipcomp);

	proposal = proposal_create(PROTO_ESP);
	if (integ)
	{
		proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, integ, 0);
	}
	if (encr)
	{
		proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, encr, len);
	}
	keymat = ike_sa->get_keymat(ike_sa);

	if (!keymat->derive_child_keys(keymat, proposal, secret.ptr ? &dh : NULL,
					nonce_i, nonce_r, &encr_i, &integ_i, &encr_r, &integ_r))
	{
		DBG1(DBG_CHD, "HA sync CHILD_SA key derivation failed");
		child_sa->destroy(child_sa);
		proposal->destroy(proposal);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return;
	}
	child_sa->set_proposal(child_sa, proposal);
	child_sa->set_state(child_sa, CHILD_INSTALLING);
	proposal->destroy(proposal);

	if (initiator)
	{
		if (child_sa->install(child_sa, encr_r, integ_r,
							  inbound_spi, inbound_cpi, TRUE) != SUCCESS ||
			child_sa->install(child_sa, encr_i, integ_i,
							  outbound_spi, outbound_cpi, FALSE) != SUCCESS)
		{
			failed = TRUE;
		}
	}
	else
	{
		if (child_sa->install(child_sa, encr_i, integ_i,
							  inbound_spi, inbound_cpi, TRUE) != SUCCESS ||
			child_sa->install(child_sa, encr_r, integ_r,
							  outbound_spi, outbound_cpi, FALSE) != SUCCESS)
		{
			failed = TRUE;
		}
	}
	chunk_clear(&encr_i);
	chunk_clear(&integ_i);
	chunk_clear(&encr_r);
	chunk_clear(&integ_r);

	if (failed)
	{
		DBG1(DBG_CHD, "HA sync CHILD_SA installation failed");
		child_sa->destroy(child_sa);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return;
	}

	/* TODO: Change CHILD_SA API to avoid cloning twice */
	local_ts = linked_list_create();
	remote_ts = linked_list_create();
	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_LOCAL_TS:
				local_ts->insert_last(local_ts, value.ts->clone(value.ts));
				break;
			case HA_SYNC_REMOTE_TS:
				remote_ts->insert_last(remote_ts, value.ts->clone(value.ts));
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
	child_sa->add_policies(child_sa, local_ts, remote_ts);
	local_ts->destroy_offset(local_ts, offsetof(traffic_selector_t, destroy));
	remote_ts->destroy_offset(remote_ts, offsetof(traffic_selector_t, destroy));

	child_sa->set_state(child_sa, CHILD_INSTALLED);
	ike_sa->add_child_sa(ike_sa, child_sa);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Process messages of type CHILD_DELETE
 */
static void process_child_delete(private_ha_sync_dispatcher_t *this,
								 ha_sync_message_t *message)
{
	ha_sync_message_attribute_t attribute;
	ha_sync_message_value_t value;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa = NULL;

	enumerator = message->create_attribute_enumerator(message);
	while (enumerator->enumerate(enumerator, &attribute, &value))
	{
		switch (attribute)
		{
			case HA_SYNC_IKE_ID:
				ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														  value.ike_sa_id);
				break;
			case HA_SYNC_INBOUND_SPI:
				if (ike_sa)
				{
					ike_sa->destroy_child_sa(ike_sa, PROTO_ESP, value.u32);
				}
				break;
			default:
				break;
		}
	}
	if (ike_sa)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
	enumerator->destroy(enumerator);
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
ha_sync_dispatcher_t *ha_sync_dispatcher_create(ha_sync_socket_t *socket)
{
	private_ha_sync_dispatcher_t *this = malloc_thing(private_ha_sync_dispatcher_t);

	this->public.destroy = (void(*)(ha_sync_dispatcher_t*))destroy;

	this->socket = socket;
	this->job = callback_job_create((callback_job_cb_t)dispatch,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}
