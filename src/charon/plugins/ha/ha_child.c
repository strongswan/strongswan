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
 */

#include "ha_child.h"

typedef struct private_ha_child_t private_ha_child_t;

/**
 * Private data of an ha_child_t object.
 */
struct private_ha_child_t {

	/**
	 * Public ha_child_t interface.
	 */
	ha_child_t public;

	/**
	 * socket we use for syncing
	 */
	ha_socket_t *socket;

	/**
	 * tunnel securing sync messages
	 */
	ha_tunnel_t *tunnel;
};

/**
 * Implementation of listener_t.child_keys
 */
static bool child_keys(private_ha_child_t *this, ike_sa_t *ike_sa,
					   child_sa_t *child_sa, diffie_hellman_t *dh,
					   chunk_t nonce_i, chunk_t nonce_r)
{
	ha_message_t *m;
	chunk_t secret;
	proposal_t *proposal;
	u_int16_t alg, len;
	linked_list_t *list;
	enumerator_t *enumerator;
	traffic_selector_t *ts;

	if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
	{	/* do not sync SA between nodes */
		return TRUE;
	}

	m = ha_message_create(HA_CHILD_ADD);

	m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));
	m->add_attribute(m, HA_INBOUND_SPI, child_sa->get_spi(child_sa, TRUE));
	m->add_attribute(m, HA_OUTBOUND_SPI, child_sa->get_spi(child_sa, FALSE));
	m->add_attribute(m, HA_INBOUND_CPI, child_sa->get_cpi(child_sa, TRUE));
	m->add_attribute(m, HA_OUTBOUND_CPI, child_sa->get_cpi(child_sa, FALSE));
	m->add_attribute(m, HA_IPSEC_MODE, child_sa->get_mode(child_sa));
	m->add_attribute(m, HA_IPCOMP, child_sa->get_ipcomp(child_sa));
	m->add_attribute(m, HA_CONFIG_NAME, child_sa->get_name(child_sa));

	proposal = child_sa->get_proposal(child_sa);
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		m->add_attribute(m, HA_ALG_ENCR, alg);
		if (len)
		{
			m->add_attribute(m, HA_ALG_ENCR_LEN, len);
		}
	}
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		m->add_attribute(m, HA_ALG_INTEG, alg);
	}
	m->add_attribute(m, HA_NONCE_I, nonce_i);
	m->add_attribute(m, HA_NONCE_R, nonce_r);
	if (dh && dh->get_shared_secret(dh, &secret) == SUCCESS)
	{
		m->add_attribute(m, HA_SECRET, secret);
		chunk_clear(&secret);
	}

	list = child_sa->get_traffic_selectors(child_sa, TRUE);
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &ts))
	{
		m->add_attribute(m, HA_LOCAL_TS, ts);
	}
	enumerator->destroy(enumerator);
	list = child_sa->get_traffic_selectors(child_sa, FALSE);
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &ts))
	{
		m->add_attribute(m, HA_REMOTE_TS, ts);
	}
	enumerator->destroy(enumerator);

	this->socket->push(this->socket, m);

	return TRUE;
}

/**
 * Implementation of listener_t.child_state_change
 */
static bool child_state_change(private_ha_child_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	if (!ike_sa ||
		ike_sa->get_state(ike_sa) == IKE_PASSIVE ||
		ike_sa->get_state(ike_sa) == IKE_DESTROYING)
	{	/* only sync active IKE_SAs */
		return TRUE;
	}
	if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
	{	/* do not sync SA between nodes */
		return TRUE;
	}


	if (state == CHILD_DESTROYING)
	{
		ha_message_t *m;

		m = ha_message_create(HA_CHILD_DELETE);

		m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));
		m->add_attribute(m, HA_INBOUND_SPI,
						 child_sa->get_spi(child_sa, TRUE));
		this->socket->push(this->socket, m);
	}
	return TRUE;
}

/**
 * Implementation of ha_child_t.destroy.
 */
static void destroy(private_ha_child_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_child_t *ha_child_create(ha_socket_t *socket, ha_tunnel_t *tunnel)
{
	private_ha_child_t *this = malloc_thing(private_ha_child_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.child_keys = (bool(*)(listener_t*, ike_sa_t *ike_sa, child_sa_t *child_sa, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r))child_keys;
	this->public.listener.child_state_change = (bool(*)(listener_t*,ike_sa_t *ike_sa, child_sa_t *child_sa, child_sa_state_t state))child_state_change;
	this->public.destroy = (void(*)(ha_child_t*))destroy;

	this->socket = socket;
	this->tunnel = tunnel;

	return &this->public;
}

