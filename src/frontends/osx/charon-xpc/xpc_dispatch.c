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

#include "xpc_dispatch.h"
#include "xpc_channels.h"

#include <xpc/xpc.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>

typedef struct private_xpc_dispatch_t private_xpc_dispatch_t;

/**
 * Private data of an xpc_dispatch_t object.
 */
struct private_xpc_dispatch_t {

	/**
	 * Public xpc_dispatch_t interface.
	 */
	xpc_dispatch_t public;

	/**
	 * XPC service we offer
	 */
	xpc_connection_t service;

	/**
	 * XPC IKE_SA specific channels to App
	 */
	xpc_channels_t *channels;

	/**
	 * GCD queue for XPC events
	 */
	dispatch_queue_t queue;
};

/**
 * Return version of this helper
 */
static xpc_object_t get_version(private_xpc_dispatch_t *this,
								xpc_object_t request, xpc_connection_t client)
{
	xpc_object_t reply;

	reply = xpc_dictionary_create_reply(request);
	xpc_dictionary_set_string(reply, "version", PACKAGE_VERSION);

	return reply;
}

/**
 * Create peer config with associated ike config
 */
static peer_cfg_t* create_peer_cfg(char *name, char *host)
{
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	u_int16_t local_port, remote_port = IKEV2_UDP_PORT;

	local_port = charon->socket->get_port(charon->socket, FALSE);
	if (local_port != IKEV2_UDP_PORT)
	{
		remote_port = IKEV2_NATT_PORT;
	}
	ike_cfg = ike_cfg_create(IKEV2, FALSE, FALSE, "0.0.0.0", FALSE, local_port,
							 host, FALSE, remote_port, FRAGMENTATION_NO, 0);
	ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
	peer_cfg = peer_cfg_create(name, ike_cfg,
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
 * Add a single auth cfg of given class to peer cfg
 */
static void add_auth_cfg(peer_cfg_t *peer_cfg, bool local,
						 char *id, auth_class_t class)
{
	auth_cfg_t *auth;

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, class);
	auth->add(auth, AUTH_RULE_IDENTITY, identification_create_from_string(id));
	peer_cfg->add_auth_cfg(peer_cfg, auth, local);
}

/**
 * Attach child config to peer config
 */
static child_cfg_t* create_child_cfg(char *name)
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

	child_cfg = child_cfg_create(name, &lifetime,
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
 * Controller initiate callback
 */
static bool initiate_cb(u_int32_t *sa, debug_t group, level_t level,
						ike_sa_t *ike_sa, const char *message)
{
	if (ike_sa)
	{
		*sa = ike_sa->get_unique_id(ike_sa);
		return FALSE;
	}
	return TRUE;
}

/**
 * Start initiating an IKE connection
 */
xpc_object_t start_connection(private_xpc_dispatch_t *this,
							  xpc_object_t request, xpc_connection_t client)
{
	xpc_object_t reply;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	char *name, *id, *host;
	bool success = FALSE;
	xpc_endpoint_t endpoint;
	xpc_connection_t channel;
	u_int32_t ike_sa;

	name = (char*)xpc_dictionary_get_string(request, "name");
	host = (char*)xpc_dictionary_get_string(request, "host");
	id = (char*)xpc_dictionary_get_string(request, "id");
	endpoint = xpc_dictionary_get_value(request, "channel");
	channel = xpc_connection_create_from_endpoint(endpoint);
	reply = xpc_dictionary_create_reply(request);

	if (name && id && host && channel)
	{
		peer_cfg = create_peer_cfg(name, host);

		add_auth_cfg(peer_cfg, TRUE, id, AUTH_CLASS_EAP);
		add_auth_cfg(peer_cfg, FALSE, host, AUTH_CLASS_ANY);

		child_cfg = create_child_cfg(name);
		peer_cfg->add_child_cfg(peer_cfg, child_cfg->get_ref(child_cfg));

		if (charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
					(controller_cb_t)initiate_cb, &ike_sa, 0) == NEED_MORE)
		{
			this->channels->add(this->channels, channel, ike_sa);
			success = TRUE;
		}
	}

	xpc_dictionary_set_bool(reply, "success", success);

	return reply;
}

/**
 * XPC command dispatch table
 */
static struct {
	char *name;
	xpc_object_t (*handler)(private_xpc_dispatch_t *this,
							xpc_object_t request, xpc_connection_t client);
} commands[] = {
	{ "get_version", get_version },
	{ "start_connection", start_connection },
};

/**
 * Handle a received XPC request message
 */
static void handle(private_xpc_dispatch_t *this, xpc_object_t request)
{
	xpc_connection_t client;
	xpc_object_t reply;
	const char *command;
	int i;

	client = xpc_dictionary_get_remote_connection(request);
	command = xpc_dictionary_get_string(request, "command");
	if (command)
	{
		for (i = 0; i < countof(commands); i++)
		{
			if (streq(commands[i].name, command))
			{
				reply = commands[i].handler(this, request, client);
				if (reply)
				{
					xpc_connection_send_message(client, reply);
					xpc_release(reply);
				}
				break;
			}
		}
	}
}

/**
 * Set up GCD handler for XPC events
 */
static void set_handler(private_xpc_dispatch_t *this)
{
	xpc_connection_set_event_handler(this->service, ^(xpc_object_t conn) {

		xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {

			if (xpc_get_type(event) == XPC_TYPE_ERROR)
			{
				if (event == XPC_ERROR_CONNECTION_INVALID ||
					event == XPC_ERROR_TERMINATION_IMMINENT)
				{
					xpc_connection_cancel(conn);
				}
			}
			else
			{
				handle(this, event);
			}
		});

		xpc_connection_resume(conn);
	});

	xpc_connection_resume(this->service);
}

METHOD(xpc_dispatch_t, destroy, void,
	private_xpc_dispatch_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->channels->listener);
	this->channels->destroy(this->channels);
	if (this->service)
	{
		xpc_connection_suspend(this->service);
		xpc_connection_cancel(this->service);
	}
	free(this);
}

/**
 * See header
 */
xpc_dispatch_t *xpc_dispatch_create()
{
	private_xpc_dispatch_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.channels = xpc_channels_create(),
		.queue = dispatch_queue_create("org.strongswan.charon-xpc.q",
									DISPATCH_QUEUE_CONCURRENT),
	);
	charon->bus->add_listener(charon->bus, &this->channels->listener);

	this->service = xpc_connection_create_mach_service(
									"org.strongswan.charon-xpc", this->queue,
									XPC_CONNECTION_MACH_SERVICE_LISTENER);
	if (!this->service)
	{
		destroy(this);
		return NULL;
	}

	set_handler(this);

	return &this->public;
}
