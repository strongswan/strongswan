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

#include "load_tester_config.h"

#include <daemon.h>

typedef struct private_load_tester_config_t private_load_tester_config_t;

/**
 * Private data of an load_tester_config_t object
 */
struct private_load_tester_config_t {

	/**
	 * Public part
	 */
	load_tester_config_t public;
	
	/**
	 * peer config
	 */
	peer_cfg_t *peer_cfg;
};

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(private_load_tester_config_t *this,
												identification_t *me, 
												identification_t *other)
{
	return enumerator_create_single(this->peer_cfg, NULL);
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(private_load_tester_config_t *this,
											   host_t *me, host_t *other)
{
	ike_cfg_t *ike_cfg;

	ike_cfg = this->peer_cfg->get_ike_cfg(this->peer_cfg);
	return enumerator_create_single(ike_cfg, NULL);
}

/**
 * implements backend_t.get_peer_cfg_by_name.
 */
static peer_cfg_t *get_peer_cfg_by_name(private_load_tester_config_t *this,
										char *name)
{
	if (streq(name, "load-test"))
	{
		return this->peer_cfg->get_ref(this->peer_cfg);
	}
	return NULL;
}

/**
 * Implementation of load_tester_config_t.destroy.
 */
static void destroy(private_load_tester_config_t *this)
{
	this->peer_cfg->destroy(this->peer_cfg);
	free(this);
}

/**
 * Described in header.
 */
load_tester_config_t *load_tester_config_create()
{
	private_load_tester_config_t *this = malloc_thing(private_load_tester_config_t);
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	proposal_t *proposal;
	traffic_selector_t *ts;
	auth_info_t *auth;
	auth_class_t class;
	char *remote, *pool, *authstr;
	host_t *vip = NULL;
	
	this->public.backend.create_peer_cfg_enumerator = (enumerator_t*(*)(backend_t*, identification_t *me, identification_t *other))create_peer_cfg_enumerator;
	this->public.backend.create_ike_cfg_enumerator = (enumerator_t*(*)(backend_t*, host_t *me, host_t *other))create_ike_cfg_enumerator;
	this->public.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	this->public.destroy = (void(*)(load_tester_config_t*))destroy;
	
	if (lib->settings->get_bool(lib->settings,
				"charon.plugins.load_tester.request_virtual_ip", FALSE))
	{
		vip = host_create_from_string("0.0.0.0", 0);
	}
	pool = lib->settings->get_str(lib->settings,
				"charon.plugins.load_tester.pool", NULL);
	remote = lib->settings->get_str(lib->settings, 
				"charon.plugins.load_tester.remote", "127.0.0.1");
	ike_cfg = ike_cfg_create(TRUE, FALSE, "0.0.0.0", remote);
	proposal = proposal_create_from_string(PROTO_IKE,
			lib->settings->get_str(lib->settings,
				"charon.plugins.load_tester.proposal", "aes128-sha1-modp768"));
	if (!proposal)
	{	/* fallback */
		proposal = proposal_create_from_string(PROTO_IKE, "aes128-sha1-modp768");
	}
	ike_cfg->add_proposal(ike_cfg, proposal);
	this->peer_cfg = peer_cfg_create("load-test", 2, ike_cfg,
			identification_create_from_string("load-test@strongswan.org"),
			identification_create_from_string("load-test@strongswan.org"),
			CERT_SEND_IF_ASKED, UNIQUE_NO, 1, 0, 0, /* keytries, rekey, reauth */
			0, 0, TRUE, 60,	/* jitter, overtime, mobike, dpddelay */
			vip, pool, FALSE, NULL, NULL);
	auth = this->peer_cfg->get_auth(this->peer_cfg);
	authstr = lib->settings->get_str(lib->settings,
								"charon.plugins.load_tester.auth", "pubkey");
	if (streq(authstr, "psk"))
	{
		class = AUTH_CLASS_PSK;
	}
	else
	{
		class = AUTH_CLASS_PUBKEY;
	}
	auth->add_item(auth, AUTHN_AUTH_CLASS, &class);
	child_cfg = child_cfg_create("load-test", 600, 400, 100, NULL, TRUE,
								 MODE_TUNNEL, ACTION_NONE, ACTION_NONE, FALSE);
	proposal = proposal_create_from_string(PROTO_ESP, "aes128-sha1");
	child_cfg->add_proposal(child_cfg, proposal);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	this->peer_cfg->add_child_cfg(this->peer_cfg, child_cfg);
	
	return &this->public;
}

