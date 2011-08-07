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

#define IFMAP_NS	  "http://www.trustedcomputinggroup.org/2010/IFMAP/2"
#define IFMAP_META_NS "http://www.trustedcomputinggroup.org/2010/IFMAP-METADATA/2"
#define IFMAP_LOGFILE "strongswan_ifmap.log"
#define IFMAP_SERVER  "https://localhost:8443/"
	
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
	 * Axis2/C environment 
	 */
	axutil_env_t *env;

	/**
	 * Axis2 service client
	 */
	axis2_svc_client_t* svc_client;

	/**
	 * SOAP Session ID
	 */
	char *session_id;

	/**
	 * IF-MAP Publisher ID
	 */
	char *ifmap_publisher_id;

	/**
	 * PEP and PDP device name
	 */
	char *device_name;

};

static bool newSession(private_tnc_ifmap_listener_t *this)
{
    axiom_node_t *request, *result, *node;
    axiom_element_t *el;
	axiom_namespace_t *ns;
	axiom_attribute_t *attr;
	axis2_char_t *value;
	axutil_qname_t *qname;

	bool success = FALSE;

	/* build newSession request */
    ns = axiom_namespace_create(this->env, IFMAP_NS, "ifmap");
    el = axiom_element_create(this->env, NULL, "newSession", ns, &request);
	attr = axiom_attribute_create(this->env, "max-poll-result-size", "1000000", NULL);	
	axiom_element_add_attribute(el, this->env, attr, request);

	/* send newSession request */
	result = axis2_svc_client_send_receive(this->svc_client, this->env, request);
	if (!result)
	{
		return FALSE;
	}

	/* process newSessionResult */
	node = axiom_node_get_first_child(result, this->env);
	if (node && axiom_node_get_node_type(node, this->env) == AXIOM_ELEMENT)
	{
		el = (axiom_element_t *)axiom_node_get_data_element(node, this->env);
		qname = axiom_element_get_qname(el, this->env, node);
		success = streq("newSessionResult",
						 axutil_qname_to_string(qname, this->env));
			
		/* process the attributes */
		if (success)
		{
			value = axiom_element_get_attribute_value_by_name(el, this->env,
								 "session-id");
			this->session_id = strdup(value);
			value = axiom_element_get_attribute_value_by_name(el, this->env,
								 "ifmap-publisher-id");
			this->ifmap_publisher_id = strdup(value);

			DBG1(DBG_TNC, "session-id: %s, ifmap-publisher-id: %s",
				 this->session_id, this->ifmap_publisher_id);
			success = this->session_id && this->ifmap_publisher_id;

			value = axiom_element_get_attribute_value_by_name(el, this->env,
								 "max-poll-result-size");
			if (value)
			{
				DBG1(DBG_TNC, "max-poll-result-size: %s", value);
			}
		}
		else
		{
			DBG1(DBG_TNC, "%s", axiom_element_to_string(el, this->env, node));
		}
	}
	axiom_node_free_tree(result, this->env);

    return success;
}

static bool purgePublisher(private_tnc_ifmap_listener_t *this)
{
	axiom_node_t *request, *result, *node;
	axiom_element_t *el;
	axiom_namespace_t *ns;
	axiom_attribute_t *attr;
	axutil_qname_t *qname;
	bool success = FALSE;

	/* build purgePublisher request */
 	ns = axiom_namespace_create(this->env, IFMAP_NS, "ifmap");
	el = axiom_element_create(this->env, NULL, "purgePublisher", ns,
							  &request);
	attr = axiom_attribute_create(this->env, "session-id",
								  this->session_id, NULL);	
	axiom_element_add_attribute(el, this->env, attr, request);
	attr = axiom_attribute_create(this->env, "ifmap-publisher-id",
								  this->ifmap_publisher_id, NULL);	
	axiom_element_add_attribute(el, this->env, attr, request);

	/* send purgePublisher request */
	result = axis2_svc_client_send_receive(this->svc_client, this->env, request);
	if (!result)
	{
		return FALSE;
	}

 	/* process purgePublisherReceived */
	node = axiom_node_get_first_child(result, this->env);
	if (node && axiom_node_get_node_type(node, this->env) == AXIOM_ELEMENT)
	{
		el = (axiom_element_t *)axiom_node_get_data_element(node, this->env);
		qname = axiom_element_get_qname(el, this->env, node);
		success = streq("purgePublisherReceived",
						 axutil_qname_to_string(qname, this->env));
		if (!success)
 		{
			DBG1(DBG_TNC, "%s", axiom_element_to_string(el, this->env, node));
		}
	}
	axiom_node_free_tree(result, this->env);

   return success;
}

static bool publish(private_tnc_ifmap_listener_t *this, u_int32_t ike_sa_id,
					identification_t *id, host_t *host, bool up)
{
	axiom_node_t *request, *result, *node, *node2, *node3, *node4;
	axiom_element_t *el;
	axiom_namespace_t *ns, *ns_meta;
	axiom_attribute_t *attr;
	axiom_text_t *text;
	axutil_qname_t *qname;
	char buf[BUF_LEN], *id_type;
	bool success = FALSE;

	/* build publish request */
 	ns = axiom_namespace_create(this->env, IFMAP_NS, "ifmap");
 	el = axiom_element_create(this->env, NULL, "publish", ns, &request);
	ns_meta = axiom_namespace_create(this->env, IFMAP_META_NS, "meta");
	axiom_element_declare_namespace(el, this->env, request, ns_meta);	
	attr = axiom_attribute_create(this->env, "session-id", this->session_id,
								  NULL);	
	axiom_element_add_attribute(el, this->env, attr, request);

	/**
	 * update or delete authenticated-as metadata
	 */
 	if (up)
	{
		el = axiom_element_create(this->env, NULL, "update", NULL, &node);
		axiom_node_add_child(request, this->env, node);
	}
	else
	{
		el = axiom_element_create(this->env, NULL, "delete", NULL, &node);
		axiom_node_add_child(request, this->env, node);

		/* add filter */
		snprintf(buf, BUF_LEN, "meta:authenticated-as[@ifmap-publisher-id='%s']",
				 this->ifmap_publisher_id);
		attr = axiom_attribute_create(this->env, "filter", buf, NULL);	
		axiom_element_add_attribute(el, this->env, attr, node);
	}

	/* add access-request */
	el = axiom_element_create(this->env, NULL, "access-request", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);

	snprintf(buf, BUF_LEN, "%s:%d", this->device_name, ike_sa_id);
	attr = axiom_attribute_create(this->env, "name", buf, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	/* add identity */
	el = axiom_element_create(this->env, NULL, "identity", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);

	snprintf(buf, BUF_LEN, "%Y", id);
	attr = axiom_attribute_create(this->env, "name", buf, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	switch (id->get_type(id))
	{
		case ID_FQDN:
			id_type = "dns-name";
			break;
		case ID_RFC822_ADDR:
			id_type = "email-address";
			break;
		case ID_DER_ASN1_DN:
			id_type = "distinguished-name";
			break;
		default:
			id_type = "other";
	}
	attr = axiom_attribute_create(this->env, "type", id_type, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	if (up)
	{
		/* add metadata */
		el = axiom_element_create(this->env, NULL, "metadata", NULL, &node2);
		axiom_node_add_child(node, this->env, node2);

		ns_meta = axiom_namespace_create(this->env, IFMAP_META_NS, "meta");

		el = axiom_element_create(this->env, NULL, "authenticated-as", ns_meta,
								  &node3);
		axiom_node_add_child(node2, this->env, node3);
		attr = axiom_attribute_create(this->env, "ifmap-cardinality",
									  "singleValue", NULL);	
		axiom_element_add_attribute(el, this->env, attr, node3);
	}

	/**
	 * update or delete access-request-ip metadata
	 */
 	if (up)
	{
		el = axiom_element_create(this->env, NULL, "update", NULL, &node);
		axiom_node_add_child(request, this->env, node);
	}
	else
	{
		el = axiom_element_create(this->env, NULL, "delete", NULL, &node);
		axiom_node_add_child(request, this->env, node);

		/* add filter */
		snprintf(buf, BUF_LEN, "meta:access-request-ip[@ifmap-publisher-id='%s']",
				 this->ifmap_publisher_id);
		attr = axiom_attribute_create(this->env, "filter", buf, NULL);
		axiom_element_add_attribute(el, this->env, attr, node);
	}

	/* add access-request */
	el = axiom_element_create(this->env, NULL, "access-request", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);

	snprintf(buf, BUF_LEN, "%s:%d", this->device_name, ike_sa_id);
	attr = axiom_attribute_create(this->env, "name", buf, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	/* add ip-address */
	el = axiom_element_create(this->env, NULL, "ip-address", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);

	snprintf(buf, BUF_LEN, "%H", host);
	attr = axiom_attribute_create(this->env, "value", buf, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	attr = axiom_attribute_create(this->env, "type",
				 host->get_family(host) == AF_INET ? "IPv4" : "IPv6", NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	if (up)
	{
		/* add metadata */
		el = axiom_element_create(this->env, NULL, "metadata", NULL, &node2);
		axiom_node_add_child(node, this->env, node2);
		ns_meta = axiom_namespace_create(this->env, IFMAP_META_NS, "meta");
		el = axiom_element_create(this->env, NULL, "access-request-ip", ns_meta,
								  &node3);
		axiom_node_add_child(node2, this->env, node3);
		attr = axiom_attribute_create(this->env, "ifmap-cardinality",
									  "singleValue", NULL);	
		axiom_element_add_attribute(el, this->env, attr, node3);
	}

	/**
	 * update or delete authenticated-by metadata
	 */
 	if (up)
	{
		el = axiom_element_create(this->env, NULL, "update", NULL, &node);
		axiom_node_add_child(request, this->env, node);
	}
	else
	{
		el = axiom_element_create(this->env, NULL, "delete", NULL, &node);
		axiom_node_add_child(request, this->env, node);

		/* add filter */		
		snprintf(buf, BUF_LEN, "meta:authenticated-by[@ifmap-publisher-id='%s']",
				 this->ifmap_publisher_id);
		attr = axiom_attribute_create(this->env, "filter", buf, NULL);
		axiom_element_add_attribute(el, this->env, attr, node);
	}

	/* add access-request */
	el = axiom_element_create(this->env, NULL, "access-request", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);

	snprintf(buf, BUF_LEN, "%s:%d", this->device_name, ike_sa_id);
	attr = axiom_attribute_create(this->env, "name", buf, NULL);	
	axiom_element_add_attribute(el, this->env, attr, node2);

	/* add device */
	el = axiom_element_create(this->env, NULL, "device", NULL, &node2);
	axiom_node_add_child(node, this->env, node2);
	el = axiom_element_create(this->env, NULL, "name", NULL, &node3);
	axiom_node_add_child(node2, this->env, node3);
	text = axiom_text_create(this->env, node3, this->device_name, &node4);

	if (up)
	{
		/* add metadata */
		el = axiom_element_create(this->env, NULL, "metadata", NULL, &node2);
		axiom_node_add_child(node, this->env, node2);
		ns_meta = axiom_namespace_create(this->env, IFMAP_META_NS, "meta");
		el = axiom_element_create(this->env, NULL, "authenticated-by", ns_meta,
								  &node3);
		axiom_node_add_child(node2, this->env, node3);
		attr = axiom_attribute_create(this->env, "ifmap-cardinality",
									  "singleValue", NULL);	
		axiom_element_add_attribute(el, this->env, attr, node3);
	}

	/* send publish request */
	result = axis2_svc_client_send_receive(this->svc_client, this->env, request);
	if (!result)
	{
		return FALSE;
	}

 	/* process publishReceived */
	node = axiom_node_get_first_child(result, this->env);
	if (node && axiom_node_get_node_type(node, this->env) == AXIOM_ELEMENT)
	{
		el = (axiom_element_t *)axiom_node_get_data_element(node, this->env);
		qname = axiom_element_get_qname(el, this->env, node);
		success = streq("publishReceived",
						axutil_qname_to_string(qname, this->env));
		if (!success)
		{
			DBG1(DBG_TNC, "%s", axiom_element_to_string(el, this->env, node));
		}
	}
	axiom_node_free_tree(result, this->env);

   return TRUE;
}

static bool endSession(private_tnc_ifmap_listener_t *this)
{
	axiom_node_t *request, *result, *node;
	axiom_element_t *el;
	axiom_namespace_t *ns;
	axiom_attribute_t *attr;
	axutil_qname_t *qname;
	bool success = FALSE;

	/* build endSession request */
 	ns = axiom_namespace_create(this->env, IFMAP_NS, "ifmap");
	el = axiom_element_create(this->env, NULL, "endSession", ns, &request);
	attr = axiom_attribute_create(this->env, "session-id", this->session_id, NULL);	
	axiom_element_add_attribute(el, this->env, attr, request);

	/* send endSession request */
	result = axis2_svc_client_send_receive(this->svc_client, this->env, request);
	if (!result)
	{
		return FALSE;
	}

 	/* process endSessionResult */
	node = axiom_node_get_first_child(result, this->env);
	if (node && axiom_node_get_node_type(node, this->env) == AXIOM_ELEMENT)
	{
		el = (axiom_element_t *)axiom_node_get_data_element(node, this->env);
		qname = axiom_element_get_qname(el, this->env, node);
		success = streq("endSessionResult",
						 axutil_qname_to_string(qname, this->env));
		if (!success)
 		{
			DBG1(DBG_TNC, "%s", axiom_element_to_string(el, this->env, node));
		}
	}
	axiom_node_free_tree(result, this->env);

   return success;

   return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_tnc_ifmap_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	u_int32_t ike_sa_id;
	identification_t *id;
	host_t *host;

	ike_sa_id = ike_sa->get_unique_id(ike_sa);
	id = ike_sa->get_other_id(ike_sa);
	host = ike_sa->get_other_host(ike_sa);

	DBG2(DBG_TNC, "sending publish");
	if (!publish(this, ike_sa_id, id, host, up))
	{
		DBG1(DBG_TNC, "publish with MAP server failed");
	}

	return TRUE;
}

METHOD(tnc_ifmap_listener_t, destroy, void,
	private_tnc_ifmap_listener_t *this)
{
	if (this->session_id)
	{
		DBG2(DBG_TNC, "sending endSession");
		if (!endSession(this))
		{
			DBG1(DBG_TNC, "endSession with MAP server failed");
		}
		free(this->session_id);
		free(this->ifmap_publisher_id);	
	}
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
		DBG1(DBG_TNC, "MAP client %s%s%s not defined",
			(!username) ? "username" : "",
			(!username && ! password) ? " and " : "",
			(!password) ? "password" : "");
	}

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
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
	DBG1(DBG_TNC, "connecting as MAP client '%s' to MAP server at '%s'",
		 username, server);

	DBG2(DBG_TNC, "sending newSession");
	if (!newSession(this))
	{
		DBG1(DBG_TNC, "newSession with MAP server failed");
		destroy(this);
		return NULL;
	}

	/* set PEP and PDP device name (defaults to IF-MAP Publisher ID) */
	this->device_name = lib->settings->get_str(lib->settings,
		 "charon.plugins.tnc-ifmap.device_name", this->ifmap_publisher_id);
	this->device_name = strdup(this->device_name);

	DBG2(DBG_TNC, "sending purgePublisher");
	if (!purgePublisher(this))
	{
		DBG1(DBG_TNC, "purgePublisher with MAP server failed");
		destroy(this);
		return NULL;
	}

	return &this->public;
}

