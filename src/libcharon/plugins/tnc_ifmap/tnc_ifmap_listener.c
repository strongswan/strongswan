/*
 * Copyright (C) 2011 Andreas Steffen 
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_ifmap_listener.h"

#include <daemon.h>
#include <config/child_cfg.h>

#include <axis2_util.h>
#include <axis2_client.h>
#include <axiom_soap.h>

#define IFMAP_NAMESPACE	"http://www.trustedcomputinggroup.org/2010/IFMAP/2"
#define IFMAP_LOGFILE	"strongswan_ifmap.log"
#define IFMAP_SERVER	"https://localhost:8443/"
	
typedef struct private_tnc_ifmap_listener_t private_tnc_ifmap_listener_t;

/**
 * Private data of an tnc_ifmap_listener_t object.
 */
struct private_tnc_ifmap_listener_t {

	/**
	 * Public tnc_ifmap_listener_t interface.
	 */
	tnc_ifmap_listener_t public;

	/**
	 * Axis2c environment 
	 */
	axutil_env_t *env;

	/**
	 * Axis2c service client
	 */
	axis2_svc_client_t* svc_client;

};

static axiom_node_t* build_request(private_tnc_ifmap_listener_t *this)
{
    axiom_node_t *node = NULL;
    axiom_element_t *el;
	axiom_namespace_t *ns;

    ns = axiom_namespace_create(this->env, IFMAP_NAMESPACE, "ifmap");
    el = axiom_element_create(this->env, NULL, "newSession", ns, &node);

    return node;
}

METHOD(listener_t, child_updown, bool,
	private_tnc_ifmap_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	child_cfg_t *config;
	host_t *vip, *me, *other;

	config = child_sa->get_config(child_sa);
	vip = ike_sa->get_virtual_ip(ike_sa, TRUE);
	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	return TRUE;
}

METHOD(tnc_ifmap_listener_t, destroy, void,
	private_tnc_ifmap_listener_t *this)
{
	if (this->svc_client)
	{
		axis2_svc_client_free(this->svc_client, this->env);
	}
	if (this->env)
	{
		axutil_env_free(this->env);
	}	
	free(this);
}

/**
 * See header
 */
tnc_ifmap_listener_t *tnc_ifmap_listener_create()
{
	private_tnc_ifmap_listener_t *this;
	axis2_char_t *server, *client_home, *username, *password, *auth_type;
	axis2_endpoint_ref_t* endpoint_ref = NULL;
	axis2_options_t *options = NULL;
	axiom_node_t *request, *response, *node;
	axiom_text_t *text;

	client_home = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-ifmap.client_home",
					AXIS2_GETENV("AXIS2C_HOME"));
	server = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-ifmap.server", IFMAP_SERVER);
	auth_type = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-ifmap.auth_type", "Basic");
	username = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-ifmap.username", NULL);
	password = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-ifmap.password", NULL);

	if (!username || !password)
	{
		DBG1(DBG_TNC, "IF-MAP client %s%s%s not defined",
			(!username) ? "username" : "",
			(!username && ! password) ? " and " : "",
			(!password) ? "password" : "");
	}

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown,
			},
			.destroy = _destroy,
		},
	);

	/* Create Axis2/C environment and options */
	this->env = axutil_env_create_all(IFMAP_LOGFILE, AXIS2_LOG_LEVEL_TRACE);
    options = axis2_options_create(this->env);
 
	/* Define the IF-MAP server as the to endpoint reference */
	endpoint_ref = axis2_endpoint_ref_create(this->env, server);
	axis2_options_set_to(options, this->env, endpoint_ref);

	/* Create the axis2 service client */
	this->svc_client = axis2_svc_client_create(this->env, client_home);
	if (!this->svc_client)
	{
		DBG1(DBG_TNC, "Error creating axis2 service client");
		AXIS2_LOG_ERROR(this->env->log, AXIS2_LOG_SI,
					    "Stub invoke FAILED: Error code: %d :: %s",
						this->env->error->error_number,
						AXIS2_ERROR_GET_MESSAGE(this->env->error));
		destroy(this);
		return NULL;
	}

	axis2_svc_client_set_options(this->svc_client, this->env, options);
	axis2_options_set_http_auth_info(options, this->env, username, password,
									 auth_type);

	request = build_request(this);
	response = axis2_svc_client_send_receive(this->svc_client, this->env, request);
	if (!response)
	{
		DBG1(DBG_TNC, "Session setup with IF-MAP server failed");
		destroy(this);
		return NULL;
	}
	node = axiom_node_get_first_child(response, this->env);
	if (node && axiom_node_get_node_type(node, this->env) == AXIOM_TEXT)
	{
		text = (axiom_text_t *)axiom_node_get_data_element(node, this->env);
		if (text)
		{
			DBG1(DBG_TNC, "response = '%s'",
				 axiom_text_get_value(text, this->env));
		}
	}
	axiom_node_free_tree(response, this->env);

	return &this->public;
}

