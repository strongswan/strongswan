/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "cmd_connection.h"

#include <signal.h>
#include <unistd.h>

#include <utils/debug.h>
#include <processing/jobs/callback_job.h>
#include <daemon.h>

typedef struct private_cmd_connection_t private_cmd_connection_t;

/**
 * Private data of an cmd_connection_t object.
 */
struct private_cmd_connection_t {

	/**
	 * Public cmd_connection_t interface.
	 */
	cmd_connection_t public;

	/**
	 * Process ID to terminate on failure
	 */
	pid_t pid;

	/**
	 * Hostname to connect to
	 */
	char *host;

	/**
	 * Local identity
	 */
	char *identity;
};

/**
 * Shut down application
 */
static void terminate(private_cmd_connection_t *this)
{
	kill(this->pid, SIGUSR1);
}

/**
 * Create peer config with associated ike config
 */
static peer_cfg_t* create_peer_cfg(private_cmd_connection_t *this)
{
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	u_int16_t local_port, remote_port = IKEV2_UDP_PORT;

	local_port = charon->socket->get_port(charon->socket, FALSE);
	if (local_port != IKEV2_UDP_PORT)
	{
		remote_port = IKEV2_NATT_PORT;
	}
	ike_cfg = ike_cfg_create(IKEV2, TRUE, FALSE, "0.0.0.0", FALSE, local_port,
					this->host, FALSE, remote_port, FRAGMENTATION_NO, 0);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	peer_cfg = peer_cfg_create("cmd", ike_cfg,
					CERT_SEND_IF_ASKED, UNIQUE_REPLACE, 1, /* keyingtries */
					36000, 0, /* rekey 10h, reauth none */
					600, 600, /* jitter, over 10min */
					TRUE, FALSE, /* mobike, aggressive */
					30, 0, /* DPD delay, timeout */
					FALSE, NULL, NULL); /* mediation */
	peer_cfg->add_virtual_ip(peer_cfg, host_create_from_string("0.0.0.0", 0));

	return peer_cfg;
}

/**
 * Attach authentication configs to peer config
 */
static void add_auth_cfgs(private_cmd_connection_t *this, peer_cfg_t *peer_cfg)
{
	auth_cfg_t *auth;

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
	auth->add(auth, AUTH_RULE_IDENTITY,
			  identification_create_from_string(this->identity));
	peer_cfg->add_auth_cfg(peer_cfg, auth, TRUE);

	auth = auth_cfg_create();

	auth->add(auth, AUTH_RULE_IDENTITY,
			  identification_create_from_string(this->host));
	peer_cfg->add_auth_cfg(peer_cfg, auth, FALSE);
}

/**
 * Attach child config to peer config
 */
static child_cfg_t* create_child_cfg(private_cmd_connection_t *this)
{
	child_cfg_t *child_cfg;
	traffic_selector_t *ts;
	lifetime_cfg_t lifetime = {
		.time = {
			.life = 10800 /* 3h */,
			.rekey = 10200 /* 2h50min */,
			.jitter = 300 /* 5min */
		}
	};

	child_cfg = child_cfg_create("cmd", &lifetime,
								 NULL, FALSE, MODE_TUNNEL, /* updown, hostaccess */
								 ACTION_NONE, ACTION_NONE, ACTION_NONE, FALSE,
								 0, 0, NULL, NULL, 0);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	ts = traffic_selector_create_dynamic(0, 0, 65535);
	child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
	ts = traffic_selector_create_from_string(0, TS_IPV4_ADDR_RANGE,
									"0.0.0.0", 0, "255.255.255.255", 65535);
	child_cfg->add_traffic_selector(child_cfg, FALSE, ts);

	return child_cfg;
}

/**
 * Initiate the configured connection
 */
static job_requeue_t initiate(private_cmd_connection_t *this)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;

	if (!this->host)
	{
		DBG1(DBG_CFG, "unable to initiate, missing --host option");
		terminate(this);
		return JOB_REQUEUE_NONE;
	}
	if (!this->identity)
	{
		DBG1(DBG_CFG, "unable to initiate, missing --identity option");
		terminate(this);
		return JOB_REQUEUE_NONE;
	}

	peer_cfg = create_peer_cfg(this);

	add_auth_cfgs(this, peer_cfg);

	child_cfg = create_child_cfg(this);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg->get_ref(child_cfg));

	if (charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 controller_cb_empty, NULL, 0) != SUCCESS)
	{
		terminate(this);
	}
	return JOB_REQUEUE_NONE;
}

METHOD(cmd_connection_t, handle, bool,
	private_cmd_connection_t *this, cmd_option_type_t opt, char *arg)
{
	switch (opt)
	{
		case CMD_OPT_HOST:
			this->host = arg;
			break;
		case CMD_OPT_IDENTITY:
			this->identity = arg;
			break;
		default:
			return FALSE;
	}
	return TRUE;
}

METHOD(cmd_connection_t, destroy, void,
	private_cmd_connection_t *this)
{
	free(this);
}

/**
 * See header
 */
cmd_connection_t *cmd_connection_create()
{
	private_cmd_connection_t *this;

	INIT(this,
		.public = {
			.handle = _handle,
			.destroy = _destroy,
		},
		.pid = getpid(),
	);

	/* queue job, gets initiated as soon as we are up and running */
	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio(
			(callback_job_cb_t)initiate, this, NULL,
			(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

	return &this->public;
}
