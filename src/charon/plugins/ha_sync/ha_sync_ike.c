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

#include "ha_sync_ike.h"

typedef struct private_ha_sync_ike_t private_ha_sync_ike_t;

/**
 * Private data of an ha_sync_ike_t object.
 */
struct private_ha_sync_ike_t {

	/**
	 * Public ha_sync_ike_t interface.
	 */
	ha_sync_ike_t public;

	/**
	 * socket we use for syncing
	 */
	ha_sync_socket_t *socket;
};

/**
 * Return condition if it is set on ike_sa
 */
static ike_condition_t copy_condition(ike_sa_t *ike_sa, ike_condition_t cond)
{
	if (ike_sa->has_condition(ike_sa, cond))
	{
		return cond;
	}
	return 0;
}

/**
 * Return extension if it is supported by peers IKE_SA
 */
static ike_extension_t copy_extension(ike_sa_t *ike_sa, ike_extension_t ext)
{
	if (ike_sa->supports_extension(ike_sa, ext))
	{
		return ext;
	}
	return 0;
}

/**
 * Implementation of listener_t.ike_keys
 */
static bool ike_keys(private_ha_sync_ike_t *this, ike_sa_t *ike_sa,
					 diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r,
					 ike_sa_t *rekey)
{
	ha_sync_message_t *m;
	chunk_t secret;
	proposal_t *proposal;
	u_int16_t alg, len;

	if (dh->get_shared_secret(dh, &secret) != SUCCESS)
	{
		return TRUE;
	}

	if (rekey == NULL)
	{
		m = ha_sync_message_create(HA_SYNC_IKE_ADD);

		m->add_attribute(m, HA_SYNC_IKE_ID, ike_sa->get_id(ike_sa));
	}
	else
	{
		m = ha_sync_message_create(HA_SYNC_IKE_REKEY);

		m->add_attribute(m, HA_SYNC_IKE_ID, ike_sa->get_id(ike_sa));
		m->add_attribute(m, HA_SYNC_IKE_REKEY_ID, rekey->get_id(rekey));
	}

	proposal = ike_sa->get_proposal(ike_sa);
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		m->add_attribute(m, HA_SYNC_ALG_ENCR, alg);
		if (len)
		{
			m->add_attribute(m, HA_SYNC_ALG_ENCR_LEN, len);
		}
	}
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		m->add_attribute(m, HA_SYNC_ALG_INTEG, alg);
	}
	if (proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{
		m->add_attribute(m, HA_SYNC_ALG_PRF, alg);
	}
	m->add_attribute(m, HA_SYNC_NONCE_I, nonce_i);
	m->add_attribute(m, HA_SYNC_NONCE_R, nonce_r);
	m->add_attribute(m, HA_SYNC_SECRET, secret);
	chunk_clear(&secret);

	this->socket->push(this->socket, m);
	m->destroy(m);

	return TRUE;
}

/**
 * Implementation of listener_t.ike_state_change
 */
static bool ike_state_change(private_ha_sync_ike_t *this, ike_sa_t *ike_sa,
							 ike_sa_state_t state)
{
	ha_sync_message_t *m;

	switch (state)
	{
		case IKE_ESTABLISHED:
		{
			iterator_t *iterator;
			peer_cfg_t *peer_cfg;
			u_int32_t extension, condition;
			host_t *local_vip, *remote_vip, *addr;
			identification_t *eap_id;

			peer_cfg = ike_sa->get_peer_cfg(ike_sa);

			condition = copy_condition(ike_sa, COND_NAT_ANY)
					  | copy_condition(ike_sa, COND_NAT_HERE)
					  | copy_condition(ike_sa, COND_NAT_THERE)
					  | copy_condition(ike_sa, COND_NAT_FAKE)
					  | copy_condition(ike_sa, COND_EAP_AUTHENTICATED)
					  | copy_condition(ike_sa, COND_CERTREQ_SEEN)
					  | copy_condition(ike_sa, COND_ORIGINAL_INITIATOR);

			extension = copy_extension(ike_sa, EXT_NATT)
					  | copy_extension(ike_sa, EXT_MOBIKE)
					  | copy_extension(ike_sa, EXT_HASH_AND_URL);

			local_vip = ike_sa->get_virtual_ip(ike_sa, TRUE);
			remote_vip = ike_sa->get_virtual_ip(ike_sa, FALSE);
			eap_id = ike_sa->get_eap_identity(ike_sa);

			m = ha_sync_message_create(HA_SYNC_IKE_UPDATE);
			m->add_attribute(m, HA_SYNC_IKE_ID, ike_sa->get_id(ike_sa));
			m->add_attribute(m, HA_SYNC_LOCAL_ID, ike_sa->get_my_id(ike_sa));
			m->add_attribute(m, HA_SYNC_REMOTE_ID, ike_sa->get_other_id(ike_sa));
			m->add_attribute(m, HA_SYNC_LOCAL_ADDR, ike_sa->get_my_host(ike_sa));
			m->add_attribute(m, HA_SYNC_REMOTE_ADDR, ike_sa->get_other_host(ike_sa));
			m->add_attribute(m, HA_SYNC_CONDITIONS, condition);
			m->add_attribute(m, HA_SYNC_EXTENSIONS, extension);
			m->add_attribute(m, HA_SYNC_CONFIG_NAME, peer_cfg->get_name(peer_cfg));
			if (local_vip)
			{
				m->add_attribute(m, HA_SYNC_LOCAL_VIP, local_vip);
			}
			if (remote_vip)
			{
				m->add_attribute(m, HA_SYNC_REMOTE_VIP, remote_vip);
			}
			if (eap_id)
			{
				m->add_attribute(m, HA_SYNC_EAP_ID, eap_id);
			}
			iterator = ike_sa->create_additional_address_iterator(ike_sa);
			while (iterator->iterate(iterator, (void**)&addr))
			{
				m->add_attribute(m, HA_SYNC_ADDITIONAL_ADDR, addr);
			}
			iterator->destroy(iterator);
			break;
		}
		case IKE_DESTROYING:
		{
			m = ha_sync_message_create(HA_SYNC_IKE_DELETE);
			m->add_attribute(m, HA_SYNC_IKE_ID, ike_sa->get_id(ike_sa));
			break;
		}
		default:
			return TRUE;
	}
	this->socket->push(this->socket, m);
	m->destroy(m);
	return TRUE;
}

/**
 * Implementation of ha_sync_ike_t.destroy.
 */
static void destroy(private_ha_sync_ike_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_sync_ike_t *ha_sync_ike_create(ha_sync_socket_t *socket)
{
	private_ha_sync_ike_t *this = malloc_thing(private_ha_sync_ike_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.ike_keys = (bool(*)(listener_t*, ike_sa_t *ike_sa, diffie_hellman_t *dh,chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey))ike_keys;
	this->public.listener.ike_state_change = (bool(*)(listener_t*,ike_sa_t *ike_sa, ike_sa_state_t state))ike_state_change;
	this->public.destroy = (void(*)(ha_sync_ike_t*))destroy;

	this->socket = socket;

	return &this->public;
}

