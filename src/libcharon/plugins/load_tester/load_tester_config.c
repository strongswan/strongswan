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
	 * Authentication method(s) to use/expect from initiator
	 */
	char *initiator_auth;

	/**
	 * Authentication method(s) use/expected from responder
	 */
	char *responder_auth;

	/**
	 * Initiator ID to enforce
	 */
	char *initiator_id;

	/**
	 * Responder ID to enforce
	 */
	char *responder_id;

	/**
	 * IKE_SA rekeying delay
	 */
	u_int ike_rekey;

	/**
	 * CHILD_SA rekeying delay
	 */
	u_int child_rekey;

	/**
	 * DPD check delay
	 */
	u_int dpd_delay;

	/**
	 * incremental numbering of generated configs
	 */
	u_int num;

	/**
	 * Dynamic source port, if used
	 */
	u_int16_t port;
};

/**
 * Generate auth config from string
 */
static void generate_auth_cfg(private_load_tester_config_t *this, char *str,
							  peer_cfg_t *peer_cfg, bool local, int num)
{
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	identification_t *id;
	auth_class_t class;
	eap_type_t type;
	char buf[128];
	int rnd = 0;

	enumerator = enumerator_create_token(str, "|", " ");
	while (enumerator->enumerate(enumerator, &str))
	{
		id = NULL;
		auth = auth_cfg_create();
		rnd++;

		if (this->initiator_id)
		{
			if ((local && num) || (!local && !num))
			{
				snprintf(buf, sizeof(buf), this->initiator_id, num, rnd);
				id = identification_create_from_string(buf);
			}
		}
		if (this->responder_id)
		{
			if ((local && !num) || (!local && num))
			{
				snprintf(buf, sizeof(buf), this->responder_id, num, rnd);
				id = identification_create_from_string(buf);
			}
		}

		if (streq(str, "psk"))
		{	/* PSK authentication, use FQDNs */
			class = AUTH_CLASS_PSK;
			if (!id)
			{
				if ((local && !num) || (!local && num))
				{
					id = identification_create_from_string("srv.strongswan.org");
				}
				else if (local)
				{
					snprintf(buf, sizeof(buf), "c%d-r%d.strongswan.org",
							 num, rnd);
					id = identification_create_from_string(buf);
				}
				else
				{
					id = identification_create_from_string("*.strongswan.org");
				}
			}
		}
		else if (strneq(str, "eap", strlen("eap")))
		{	/* EAP authentication, use a NAI */
			class = AUTH_CLASS_EAP;
			if (*(str + strlen("eap")) == '-')
			{
				type = eap_type_from_string(str + strlen("eap-"));
				if (type)
				{
					auth->add(auth, AUTH_RULE_EAP_TYPE, type);
				}
			}
			if (!id)
			{
				if (local && num)
				{
					snprintf(buf, sizeof(buf), "1%.10d%.4d@strongswan.org",
							 num, rnd);
					id = identification_create_from_string(buf);
				}
				else
				{
					id = identification_create_from_encoding(ID_ANY, chunk_empty);
				}
			}
		}
		else
		{
			if (!streq(str, "pubkey"))
			{
				DBG1(DBG_CFG, "invalid authentication: '%s', fallback to pubkey",
					 str);
			}
			/* certificate authentication, use distinguished names */
			class = AUTH_CLASS_PUBKEY;
			if (!id)
			{
				if ((local && !num) || (!local && num))
				{
					id = identification_create_from_string(
								"CN=srv, OU=load-test, O=strongSwan");
				}
				else if (local)
				{
					snprintf(buf, sizeof(buf),
							 "CN=c%d-r%d, OU=load-test, O=strongSwan", num, rnd);
					id = identification_create_from_string(buf);
				}
				else
				{
					id = identification_create_from_string(
									"CN=*, OU=load-test, O=strongSwan");
				}
			}
		}
		auth->add(auth, AUTH_RULE_AUTH_CLASS, class);
		auth->add(auth, AUTH_RULE_IDENTITY, id);
		peer_cfg->add_auth_cfg(peer_cfg, auth, local);
	}
	enumerator->destroy(enumerator);
}

/**
 * Generate a new initiator config, num = 0 for responder config
 */
static peer_cfg_t* generate_config(private_load_tester_config_t *this, uint num)
{
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	peer_cfg_t *peer_cfg;
	traffic_selector_t *ts;
	proposal_t *proposal;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = this->child_rekey * 2,
			.rekey = this->child_rekey,
			.jitter = 0
		}
	};

	if (this->port && num)
	{
		ike_cfg = ike_cfg_create(FALSE, FALSE,
				"0.0.0.0", this->port + num - 1, this->remote, IKEV2_NATT_PORT);
	}
	else
	{
		ike_cfg = ike_cfg_create(FALSE, FALSE,
				"0.0.0.0", IKEV2_UDP_PORT, this->remote, IKEV2_UDP_PORT);
	}
	ike_cfg->add_proposal(ike_cfg, this->proposal->clone(this->proposal));
	peer_cfg = peer_cfg_create("load-test", 2, ike_cfg,
							   CERT_SEND_IF_ASKED, UNIQUE_NO, 1, /* keytries */
							   this->ike_rekey, 0, /* rekey, reauth */
							   0, this->ike_rekey, /* jitter, overtime */
							   FALSE, this->dpd_delay, /* mobike, dpddelay */
							   this->vip ? this->vip->clone(this->vip) : NULL,
							   this->pool, FALSE, NULL, NULL);
	if (num)
	{	/* initiator */
		generate_auth_cfg(this, this->initiator_auth, peer_cfg, TRUE, num);
		generate_auth_cfg(this, this->responder_auth, peer_cfg, FALSE, num);
	}
	else
	{	/* responder */
		generate_auth_cfg(this, this->responder_auth, peer_cfg, TRUE, num);
		generate_auth_cfg(this, this->initiator_auth, peer_cfg, FALSE, num);
	}

	child_cfg = child_cfg_create("load-test", &lifetime, NULL, TRUE, MODE_TUNNEL,
								 ACTION_NONE, ACTION_NONE, ACTION_NONE, FALSE,
								 0, 0, NULL, NULL, 0);
	proposal = proposal_create_from_string(PROTO_ESP, "aes128-sha1");
	child_cfg->add_proposal(child_cfg, proposal);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	return peer_cfg;
}

METHOD(backend_t, create_peer_cfg_enumerator, enumerator_t*,
	private_load_tester_config_t *this,
	identification_t *me, identification_t *other)
{
	return enumerator_create_single(this->peer_cfg, NULL);
}

METHOD(backend_t, create_ike_cfg_enumerator, enumerator_t*,
	private_load_tester_config_t *this, host_t *me, host_t *other)
{
	ike_cfg_t *ike_cfg;

	ike_cfg = this->peer_cfg->get_ike_cfg(this->peer_cfg);
	return enumerator_create_single(ike_cfg, NULL);
}

METHOD(backend_t, get_peer_cfg_by_name, peer_cfg_t*,
	private_load_tester_config_t *this, char *name)
{
	if (streq(name, "load-test"))
	{
		return generate_config(this, this->num++);
	}
	return NULL;
}

METHOD(load_tester_config_t, destroy, void,
	private_load_tester_config_t *this)
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
	private_load_tester_config_t *this;

	INIT(this,
		.public = {
			.backend = {
				.create_peer_cfg_enumerator = _create_peer_cfg_enumerator,
				.create_ike_cfg_enumerator = _create_ike_cfg_enumerator,
				.get_peer_cfg_by_name = _get_peer_cfg_by_name,
			},
			.destroy = _destroy,
		},
		.num = 1,
	);

	if (lib->settings->get_bool(lib->settings,
				"charon.plugins.load-tester.request_virtual_ip", FALSE))
	{
		this->vip = host_create_from_string("0.0.0.0", 0);
	}
	this->pool = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.pool", NULL);
	this->remote = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.remote", "127.0.0.1");

	this->proposal = proposal_create_from_string(PROTO_IKE,
			lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.proposal", "aes128-sha1-modp768"));
	if (!this->proposal)
	{	/* fallback */
		this->proposal = proposal_create_from_string(PROTO_IKE,
													 "aes128-sha1-modp768");
	}
	this->ike_rekey = lib->settings->get_int(lib->settings,
				"charon.plugins.load-tester.ike_rekey", 0);
	this->child_rekey = lib->settings->get_int(lib->settings,
				"charon.plugins.load-tester.child_rekey", 600);
	this->dpd_delay = lib->settings->get_int(lib->settings,
				"charon.plugins.load-tester.dpd_delay", 0);

	this->initiator_auth = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.initiator_auth", "pubkey");
	this->responder_auth = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.responder_auth", "pubkey");
	this->initiator_id = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.initiator_id", NULL);
	this->responder_id = lib->settings->get_str(lib->settings,
				"charon.plugins.load-tester.responder_id", NULL);

	this->port = lib->settings->get_int(lib->settings,
				"charon.plugins.load-tester.dynamic_port", 0);

	this->peer_cfg = generate_config(this, 0);

	return &this->public;
}

