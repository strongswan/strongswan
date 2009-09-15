/*
 * Copyright (C) 2009 Martin Willi
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

#include "ha_sync_tunnel.h"
#include "ha_sync_plugin.h"

#include <daemon.h>
#include <utils/identification.h>
#include <processing/jobs/callback_job.h>

typedef struct private_ha_sync_tunnel_t private_ha_sync_tunnel_t;
typedef struct ha_backend_t ha_backend_t;
typedef struct ha_creds_t ha_creds_t;

/**
 * Serves credentials for the HA sync SA
 */
struct ha_creds_t {

	/**
	 * Implements credential_set_t
	 */
	credential_set_t public;

	/**
	 * own identity
	 */
	identification_t *local;

	/**
	 * peer identity
	 */
	identification_t *remote;

	/**
	 * Shared key to serve
	 */
	shared_key_t *key;
};

/**
 * Serves configurations for the HA sync SA
 */
struct ha_backend_t {

	/**
	 * Implements backend_t
	 */
	backend_t public;

	/**
	 * peer config we serve
	 */
	peer_cfg_t *cfg;
};

/**
 * Private data of an ha_sync_tunnel_t object.
 */
struct private_ha_sync_tunnel_t {

	/**
	 * Public ha_sync_tunnel_t interface.
	 */
	ha_sync_tunnel_t public;

	/**
	 * Reqid of installed trap
	 */
	u_int32_t trap;

	/**
	 * backend for sync SA
	 */
	ha_backend_t backend;

	/**
	 * credential set for sync SA
	 */
	ha_creds_t creds;
};

/**
 * Implementation of ha_sync_tunnel_t.is_sync_sa
 */
static bool is_sync_sa(private_ha_sync_tunnel_t *this, ike_sa_t *ike_sa)
{
	peer_cfg_t *cfg = this->backend.cfg;

	return cfg && ike_sa->get_ike_cfg(ike_sa) == cfg->get_ike_cfg(cfg);
}

/**
 * Enumerator over HA shared_key
 */
typedef struct {
	/** Implements enumerator_t */
	enumerator_t public;
	/** a single secret we serve */
	shared_key_t *key;
} shared_enum_t;

/**
 * Implementation of shared_enum_t.enumerate
 */
static bool shared_enumerate(shared_enum_t *this, shared_key_t **key,
							 id_match_t *me, id_match_t *other)
{
	if (this->key)
	{
		if (me)
		{
			*me = ID_MATCH_PERFECT;
		}
		if (other)
		{
			*other = ID_MATCH_PERFECT;
		}
		*key = this->key;
		this->key = NULL;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implements ha_creds_t.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(ha_creds_t *this,
							shared_key_type_t type, identification_t *me,
							identification_t *other)
{
	shared_enum_t *enumerator;

	if (type != SHARED_IKE && type != SHARED_ANY)
	{
		return NULL;
	}
	if (me && !me->equals(me, this->local))
	{
		return NULL;
	}
	if (other && !other->equals(other, this->remote))
	{
		return NULL;
	}

	enumerator = malloc_thing(shared_enum_t);
	enumerator->public.enumerate = (void*)shared_enumerate;
	enumerator->public.destroy = (void*)free;
	enumerator->key = this->key;

	return &enumerator->public;
}

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(ha_backend_t *this,
								identification_t *me, identification_t *other)
{
	return enumerator_create_single(this->cfg, NULL);
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(ha_backend_t *this,
											   host_t *me, host_t *other)
{
	return enumerator_create_single(this->cfg->get_ike_cfg(this->cfg), NULL);
}

/**
 * Install configs and a a trap for secured sync
 */
static void setup_sync_tunnel(private_ha_sync_tunnel_t *this,
							  char *local, char *remote, char *secret)
{
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;
	auth_cfg_t *auth_cfg;
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = 21600, .rekey = 20400, .jitter = 400,
		},
	};

	/* setup credentials */
	this->creds.local = identification_create_from_string(local);
	this->creds.remote = identification_create_from_string(remote);
	this->creds.key = shared_key_create(SHARED_IKE,
							chunk_clone(chunk_create(secret, strlen(secret))));
	this->creds.public.create_private_enumerator = (void*)return_null;
	this->creds.public.create_cert_enumerator = (void*)return_null;
	this->creds.public.create_shared_enumerator = (void*)create_shared_enumerator;
	this->creds.public.create_cdp_enumerator = (void*)return_null;
	this->creds.public.cache_cert = (void*)nop;

	charon->credentials->add_set(charon->credentials, &this->creds.public);

	/* create config and backend */
	ike_cfg = ike_cfg_create(FALSE, FALSE, local, remote);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	peer_cfg = peer_cfg_create("ha-sync", 2, ike_cfg, CERT_NEVER_SEND,
						UNIQUE_KEEP, 0, 86400, 0, 7200, 3600, FALSE, 30,
						NULL, NULL, FALSE, NULL, NULL);

	auth_cfg = auth_cfg_create();
	auth_cfg->add(auth_cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	auth_cfg->add(auth_cfg, AUTH_RULE_IDENTITY,
				  identification_create_from_string(local));
	peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, TRUE);

	auth_cfg = auth_cfg_create();
	auth_cfg->add(auth_cfg, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	auth_cfg->add(auth_cfg, AUTH_RULE_IDENTITY,
				  identification_create_from_string(remote));
	peer_cfg->add_auth_cfg(peer_cfg, auth_cfg, FALSE);

	child_cfg = child_cfg_create("ha-sync", &lifetime, NULL, TRUE,
						MODE_TRANSPORT, ACTION_NONE, ACTION_NONE, FALSE);
	ts = traffic_selector_create_dynamic(0, HA_SYNC_PORT, HA_SYNC_PORT);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_dynamic(0, HA_SYNC_PORT, HA_SYNC_PORT);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);

	this->backend.cfg = peer_cfg;
	this->backend.public.create_peer_cfg_enumerator = (void*)create_peer_cfg_enumerator;
	this->backend.public.create_ike_cfg_enumerator = (void*)create_ike_cfg_enumerator;
	this->backend.public.get_peer_cfg_by_name = (void*)return_null;

	charon->backends->add_backend(charon->backends, &this->backend.public);

	/* install an acquiring trap */
	this->trap = charon->traps->install(charon->traps, peer_cfg, child_cfg);
}

/**
 * Implementation of ha_sync_tunnel_t.destroy.
 */
static void destroy(private_ha_sync_tunnel_t *this)
{
	if (this->backend.cfg)
	{
		charon->backends->remove_backend(charon->backends, &this->backend.public);
		this->backend.cfg->destroy(this->backend.cfg);
	}
	if (this->creds.key)
	{
		charon->credentials->remove_set(charon->credentials, &this->creds.public);
		this->creds.key->destroy(this->creds.key);
	}
	this->creds.local->destroy(this->creds.local);
	this->creds.remote->destroy(this->creds.remote);
	if (this->trap)
	{
		charon->traps->uninstall(charon->traps, this->trap);
	}
	free(this);
}

/**
 * See header
 */
ha_sync_tunnel_t *ha_sync_tunnel_create(char *local, char *remote, char *secret)
{
	private_ha_sync_tunnel_t *this = malloc_thing(private_ha_sync_tunnel_t);

	this->public.is_sync_sa = (bool(*)(ha_sync_tunnel_t*, ike_sa_t *ike_sa))is_sync_sa;
	this->public.destroy = (void(*)(ha_sync_tunnel_t*))destroy;

	setup_sync_tunnel(this, local, remote, secret);

	return &this->public;
}

