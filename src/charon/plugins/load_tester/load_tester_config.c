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
	
	/**
	 * virtual IP, if any
	 */
	host_t *vip;
	
	/**
	 * Remote address
	 */
	char *remote;
	
	/**
	 * IP address pool
	 */
	char *pool;
	
	/**
 	 * IKE proposal
 	 */
	proposal_t *proposal;
	
	/**
	 * Authentication method to use
	 */
	auth_class_t class;
	
	/**
	 * incremental numbering of generated configs
	 */
	u_int num;
};

/**
 * Generate a new initiator config, num = 0 for responder config
 */
static peer_cfg_t* generate_config(private_load_tester_config_t *this, uint num)
{
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	peer_cfg_t *peer_cfg;
	traffic_selector_t *ts;
	auth_info_t *auth;
	identification_t *local, *remote;
	proposal_t *proposal;
	char buf[128];
	
	if (num)
	{	/* initiator */
		snprintf(buf, sizeof(buf), "CN=cli-%d, OU=load-test, O=strongSwan", num);
		local = identification_create_from_string(buf);
		snprintf(buf, sizeof(buf), "CN=srv, OU=load-test, O=strongSwan", num);
		remote = identification_create_from_string(buf);
	}
	else
	{	/* responder */
		local = identification_create_from_string(
										"CN=srv, OU=load-test, O=strongSwan");
		remote = identification_create_from_string(
										"CN=*, OU=load-test, O=strongSwan");
	}
	
	ike_cfg = ike_cfg_create(FALSE, FALSE, "0.0.0.0", this->remote);
	ike_cfg->add_proposal(ike_cfg, this->proposal->clone(this->proposal));
	peer_cfg = peer_cfg_create("load-test", 2, ike_cfg, local, remote,
			CERT_SEND_IF_ASKED, UNIQUE_NO, 1, 0, 0, /* keytries, rekey, reauth */
			0, 0, FALSE, 0,	/* jitter, overtime, mobike, dpddelay */
			this->vip ? this->vip->clone(this->vip) : NULL,
			this->pool, FALSE, NULL, NULL);
	auth = peer_cfg->get_auth(peer_cfg);
	auth->add_item(auth, AUTHN_AUTH_CLASS, &this->class);
	child_cfg = child_cfg_create("load-test", 600, 400, 100, NULL, TRUE,
								 MODE_TUNNEL, ACTION_NONE, ACTION_NONE, FALSE);
	proposal = proposal_create_from_string(PROTO_ESP, "aes128-sha1");
	child_cfg->add_proposal(child_cfg, proposal);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	return peer_cfg;
}

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
		return generate_config(this, this->num++);
	}
	return NULL;
}

/**
 * Implementation of load_tester_config_t.destroy.
 */
static void destroy(private_load_tester_config_t *this)
{
	this->peer_cfg->destroy(this->peer_cfg);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->vip);
	free(this);
}

/**
 * Described in header.
 */
load_tester_config_t *load_tester_config_create()
{
	private_load_tester_config_t *this = malloc_thing(private_load_tester_config_t);
	char *authstr;
	
	this->public.backend.create_peer_cfg_enumerator = (enumerator_t*(*)(backend_t*, identification_t *me, identification_t *other))create_peer_cfg_enumerator;
	this->public.backend.create_ike_cfg_enumerator = (enumerator_t*(*)(backend_t*, host_t *me, host_t *other))create_ike_cfg_enumerator;
	this->public.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	this->public.destroy = (void(*)(load_tester_config_t*))destroy;
	
	this->vip = NULL;
	if (lib->settings->get_bool(lib->settings,
				"charon.plugins.load_tester.request_virtual_ip", FALSE))
	{
		this->vip = host_create_from_string("0.0.0.0", 0);
	}
	this->pool = lib->settings->get_str(lib->settings,
				"charon.plugins.load_tester.pool", NULL);
	this->remote = lib->settings->get_str(lib->settings, 
				"charon.plugins.load_tester.remote", "127.0.0.1");
				
	this->proposal = proposal_create_from_string(PROTO_IKE,
			lib->settings->get_str(lib->settings,
				"charon.plugins.load_tester.proposal", "aes128-sha1-modp768"));
	if (!this->proposal)
	{	/* fallback */
		this->proposal = proposal_create_from_string(PROTO_IKE,
													 "aes128-sha1-modp768");
	}
	authstr = lib->settings->get_str(lib->settings,
								"charon.plugins.load_tester.auth", "pubkey");
	if (streq(authstr, "psk"))
	{
		this->class = AUTH_CLASS_PSK;
	}
	else
	{
		this->class = AUTH_CLASS_PUBKEY;
	}
	
	this->num = 1;
	this->peer_cfg = generate_config(this, 0);
	
	return &this->public;
}

