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

#include "ha_ike.h"

typedef struct private_ha_ike_t private_ha_ike_t;

/**
 * Private data of an ha_ike_t object.
 */
struct private_ha_ike_t {

	/**
	 * Public ha_ike_t interface.
	 */
	ha_ike_t public;

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
static bool ike_keys(private_ha_ike_t *this, ike_sa_t *ike_sa,
					 diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r,
					 ike_sa_t *rekey)
{
	ha_message_t *m;
	chunk_t secret;
	proposal_t *proposal;
	u_int16_t alg, len;

	if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
	{	/* do not sync SA between nodes */
		return TRUE;
	}
	if (dh->get_shared_secret(dh, &secret) != SUCCESS)
	{
		return TRUE;
	}

	m = ha_message_create(HA_IKE_ADD);
	m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));

	if (rekey)
	{
		chunk_t skd;
		keymat_t *keymat;

		keymat = rekey->get_keymat(rekey);
		m->add_attribute(m, HA_IKE_REKEY_ID, rekey->get_id(rekey));
		m->add_attribute(m, HA_ALG_OLD_PRF, keymat->get_skd(keymat, &skd));
		m->add_attribute(m, HA_OLD_SKD, skd);
	}

	proposal = ike_sa->get_proposal(ike_sa);
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
	if (proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{
		m->add_attribute(m, HA_ALG_PRF, alg);
	}
	m->add_attribute(m, HA_NONCE_I, nonce_i);
	m->add_attribute(m, HA_NONCE_R, nonce_r);
	m->add_attribute(m, HA_SECRET, secret);
	chunk_clear(&secret);

	this->socket->push(this->socket, m);

	return TRUE;
}

/**
 * Implementation of listener_t.ike_updown
 */
static bool ike_updown(private_ha_ike_t *this, ike_sa_t *ike_sa, bool up)
{
	ha_message_t *m;

	if (ike_sa->get_state(ike_sa) == IKE_PASSIVE)
	{	/* only sync active IKE_SAs */
		return TRUE;
	}
	if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
	{	/* do not sync SA between nodes */
		return TRUE;
	}

	if (up)
	{
		iterator_t *iterator;
		peer_cfg_t *peer_cfg;
		u_int32_t extension, condition;
		host_t *addr;
		identification_t *eap_id;
		ike_sa_id_t *id;

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

		eap_id = ike_sa->get_eap_identity(ike_sa);
		id = ike_sa->get_id(ike_sa);

		m = ha_message_create(HA_IKE_UPDATE);
		m->add_attribute(m, HA_IKE_ID, id);
		m->add_attribute(m, HA_LOCAL_ID, ike_sa->get_my_id(ike_sa));
		m->add_attribute(m, HA_REMOTE_ID, ike_sa->get_other_id(ike_sa));
		m->add_attribute(m, HA_LOCAL_ADDR, ike_sa->get_my_host(ike_sa));
		m->add_attribute(m, HA_REMOTE_ADDR, ike_sa->get_other_host(ike_sa));
		m->add_attribute(m, HA_CONDITIONS, condition);
		m->add_attribute(m, HA_EXTENSIONS, extension);
		m->add_attribute(m, HA_CONFIG_NAME, peer_cfg->get_name(peer_cfg));
		if (eap_id)
		{
			m->add_attribute(m, HA_EAP_ID, eap_id);
		}
		iterator = ike_sa->create_additional_address_iterator(ike_sa);
		while (iterator->iterate(iterator, (void**)&addr))
		{
			m->add_attribute(m, HA_ADDITIONAL_ADDR, addr);
		}
		iterator->destroy(iterator);
	}
	else
	{
		m = ha_message_create(HA_IKE_DELETE);
		m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));
	}
	this->socket->push(this->socket, m);
	return TRUE;
}

/**
 * Implementation of listener_t.ike_rekey
 */
static bool ike_rekey(private_ha_ike_t *this, ike_sa_t *old, ike_sa_t *new)
{
	ike_updown(this, old, FALSE);
	ike_updown(this, new, TRUE);
	return TRUE;
}

/**
 * Implementation of listener_t.message
 */
static bool message_hook(private_ha_ike_t *this, ike_sa_t *ike_sa,
						 message_t *message, bool incoming)
{
	if (this->tunnel && this->tunnel->is_sa(this->tunnel, ike_sa))
	{	/* do not sync SA between nodes */
		return TRUE;
	}

	if (message->get_exchange_type(message) != IKE_SA_INIT &&
		message->get_request(message))
	{	/* we sync on requests, but skip it on IKE_SA_INIT */
		ha_message_t *m;
		u_int32_t mid;

		m = ha_message_create(HA_IKE_UPDATE);
		m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));
		mid = message->get_message_id(message) + 1;
		if (incoming)
		{
			m->add_attribute(m, HA_RESPOND_MID, mid);
		}
		else
		{
			m->add_attribute(m, HA_INITIATE_MID, mid);
		}
		this->socket->push(this->socket, m);
	}
	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		message->get_exchange_type(message) == IKE_AUTH &&
		!message->get_request(message))
	{	/* After IKE_SA has been established, sync peers virtual IP.
		 * We cannot sync it in the state_change hook, it is installed later.
		 * TODO: where to sync local VIP? */
		ha_message_t *m;
		host_t *vip;

		vip = ike_sa->get_virtual_ip(ike_sa, FALSE);
		if (vip)
		{
			m = ha_message_create(HA_IKE_UPDATE);
			m->add_attribute(m, HA_IKE_ID, ike_sa->get_id(ike_sa));
			m->add_attribute(m, HA_REMOTE_VIP, vip);
			this->socket->push(this->socket, m);
		}
	}
	return TRUE;
}

/**
 * Implementation of ha_ike_t.destroy.
 */
static void destroy(private_ha_ike_t *this)
{
	free(this);
}

/**
 * See header
 */
ha_ike_t *ha_ike_create(ha_socket_t *socket, ha_tunnel_t *tunnel)
{
	private_ha_ike_t *this = malloc_thing(private_ha_ike_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.ike_keys = (bool(*)(listener_t*, ike_sa_t *ike_sa, diffie_hellman_t *dh,chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey))ike_keys;
	this->public.listener.ike_updown = (bool(*)(listener_t*,ike_sa_t *ike_sa, bool up))ike_updown;
	this->public.listener.ike_rekey = (bool(*)(listener_t*,ike_sa_t *old, ike_sa_t *new))ike_rekey;
	this->public.listener.message = (bool(*)(listener_t*, ike_sa_t *, message_t *,bool))message_hook;
	this->public.destroy = (void(*)(ha_ike_t*))destroy;

	this->socket = socket;
	this->tunnel = tunnel;

	return &this->public;
}

