/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "imv_scanner_agent.h"
#include "imv_scanner_state.h"

#include <imv/imv_agent.h>
#include <imv/imv_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_attr_request.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_port_filter.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/debug.h>
#include <utils/lexparser.h>

typedef struct private_imv_scanner_agent_t private_imv_scanner_agent_t;

/* Subscribed PA-TNC message subtypes */
static pen_type_t msg_types[] = {
	{ PEN_IETF, PA_SUBTYPE_IETF_VPN }
};

/**
 * Flag set when corresponding attribute has been received
 */
typedef enum imv_scanner_attr_t imv_scanner_attr_t;

enum imv_scanner_attr_t {
	IMV_SCANNER_ATTR_PORT_FILTER =         (1<<0)
};

typedef struct port_range_t port_range_t;

struct port_range_t {
	u_int16_t start, stop;
};

/**
 * Default port policy
 *
 * TRUE:  all server ports on the TNC client must be closed
 * FALSE: any server port on the TNC client is allowed to be open
 */
static bool closed_port_policy = TRUE;

/**
 * List of TCP and UDP port ranges
 *
 * TRUE:  server ports on the TNC client that are allowed to be open
 * FALSE: server ports on the TNC client that must be closed
 */
static linked_list_t *tcp_ports, *udp_ports;

/**
 * Get a TCP or UDP port list from strongswan.conf
 */
static linked_list_t* get_port_list(char *label)
{
	char key[40], *value;
	linked_list_t *list;
	chunk_t port_list, port_item, port_start;
	port_range_t *port_range;

	list = linked_list_create();

	snprintf(key, sizeof(key), "libimcv.plugins.imv-scanner.%s_ports", label);
	value = lib->settings->get_str(lib->settings, key, NULL);
	if (!value)
	{
		DBG1(DBG_IMV, "%s not defined", key);
		return list;
	}
	port_list = chunk_create(value, strlen(value));
	DBG2(DBG_IMV, "list of %s ports that %s:", label,
		 closed_port_policy ? "are allowed to be open" : "must be closed");

	while (eat_whitespace(&port_list))
	{
		if (!extract_token(&port_item, ' ', &port_list))
		{
			/* reached last port item */
			port_item = port_list;
			port_list = chunk_empty;
		}
		port_range = malloc_thing(port_range_t);
		port_range->start = atoi(port_item.ptr);

		if (extract_token(&port_start, '-', &port_item) && port_item.len)
		{
			port_range->stop = atoi(port_item.ptr);
		}
		else
		{
			port_range->stop = port_range->start;
		}
		DBG2(DBG_IMV, "%5u - %5u", port_range->start, port_range->stop);
		list->insert_last(list, port_range);
	}

	return list;
}

/**
 * Private data of an imv_scanner_agent_t object.
 */
struct private_imv_scanner_agent_t {

	/**
	 * Public members of imv_scanner_agent_t
	 */
	imv_agent_if_t public;

	/**
	 * IMV agent responsible for generic functions
	 */
	imv_agent_t *agent;

};

METHOD(imv_agent_if_t, bind_functions, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_TNCS_BindFunctionPointer bind_function)
{
	return this->agent->bind_functions(this->agent, bind_function);
}

METHOD(imv_agent_if_t, notify_connection_change, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_ConnectionID id,
	TNC_ConnectionState new_state)
{
	imv_state_t *state;

	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_scanner_state_create(id);
			return this->agent->create_state(this->agent, state);
		case TNC_CONNECTION_STATE_DELETE:
			return this->agent->delete_state(this->agent, id);
		default:
			return this->agent->change_state(this->agent, id, new_state, NULL);
	}
}

/**
 * Process a received message
 */
static TNC_Result receive_msg(private_imv_scanner_agent_t *this,
							  imv_state_t *state, imv_msg_t *in_msg)
{
	imv_msg_t *out_msg;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t type;
	TNC_Result result;
	bool fatal_error = FALSE;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF && type.type == IETF_ATTR_PORT_FILTER)
		{
			imv_scanner_state_t *scanner_state;
			ietf_attr_port_filter_t *attr_port_filter;
			enumerator_t *enumerator;
			u_int8_t protocol;
			u_int16_t port;
			bool blocked, compliant = TRUE;


			scanner_state = (imv_scanner_state_t*)state;
			scanner_state->set_received(scanner_state,
										IMV_SCANNER_ATTR_PORT_FILTER);
			attr_port_filter = (ietf_attr_port_filter_t*)attr;

			enumerator = attr_port_filter->create_port_enumerator(attr_port_filter);
			while (enumerator->enumerate(enumerator, &blocked, &protocol, &port))
			{
				enumerator_t *e;
				port_range_t *port_range;
				bool passed, found = FALSE;
				char buf[20];

				if (blocked)
				{
					/* ignore closed ports */
					continue;
				}

				e = (protocol == IPPROTO_TCP) ?
							tcp_ports->create_enumerator(tcp_ports) :
							udp_ports->create_enumerator(udp_ports);
				while (e->enumerate(e, &port_range))
				{
					if (port >= port_range->start && port <= port_range->stop)
					{
						found = TRUE;
						break;
					}
				}
				e->destroy(e);

				passed = (closed_port_policy == found);
				DBG2(DBG_IMV, "%s port %5u %s: %s",
					(protocol == IPPROTO_TCP) ? "tcp" : "udp", port,
					 blocked ? "closed" : "open", passed ? "ok" : "fatal");
				if (!passed)
				{
					compliant = FALSE;
					snprintf(buf, sizeof(buf), "%s/%u",
							(protocol == IPPROTO_TCP) ? "tcp" : "udp", port);
					scanner_state->add_violating_port(scanner_state, strdup(buf));
				}
			}
			enumerator->destroy(enumerator);

			if (compliant)
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_COMPLIANT);
			}
			else
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);
			}
		}
	}
	enumerator->destroy(enumerator);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
	}

	out_msg = imv_msg_create_as_reply(in_msg);
	result = out_msg->send_assessment(out_msg);
	out_msg->destroy(out_msg);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}  
	return this->agent->provide_recommendation(this->agent, state);
}

METHOD(imv_agent_if_t, receive_message, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_ConnectionID id,
	TNC_MessageType msg_type, chunk_t msg)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_data(this->agent, state, id, msg_type, msg);
	result = receive_msg(this, state, in_msg);
	in_msg->destroy(in_msg);

	return result;
}

METHOD(imv_agent_if_t, receive_message_long, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_ConnectionID id,
	TNC_UInt32 src_imc_id, TNC_UInt32 dst_imv_id,
	TNC_VendorID msg_vid, TNC_MessageSubtype msg_subtype, chunk_t msg)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(this->agent, state, id,
					src_imc_id, dst_imv_id, msg_vid, msg_subtype, msg);
	result = receive_msg(this, state, in_msg);
	in_msg->destroy(in_msg);

	return result;

}

METHOD(imv_agent_if_t, batch_ending, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_ConnectionID id)
{
	imv_state_t *state;
	imv_msg_t *out_msg;
	pa_tnc_attr_t *attr;
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	TNC_Result result = TNC_RESULT_SUCCESS;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	state->get_recommendation(state, &rec, &eval);
	if (rec == TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION)
	{
		out_msg = imv_msg_create(this->agent, state, id,
								 this->agent->get_id(this->agent),
								 TNC_IMCID_ANY, msg_types[0]);
		attr = ietf_attr_attr_request_create(PEN_IETF, IETF_ATTR_PORT_FILTER);
		out_msg->add_attribute(out_msg, attr);

		/* send PA-TNC message with excl flag not set */
		result = out_msg->send(out_msg, FALSE);
		out_msg->destroy(out_msg);
	}
	return result;
}

METHOD(imv_agent_if_t, solicit_recommendation, TNC_Result,
	private_imv_scanner_agent_t *this, TNC_ConnectionID id)
{
	imv_state_t *state;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return this->agent->provide_recommendation(this->agent, state);
}

METHOD(imv_agent_if_t, destroy, void,
	private_imv_scanner_agent_t *this)
{
	tcp_ports->destroy_function(tcp_ports, free);
	udp_ports->destroy_function(udp_ports, free);
	this->agent->destroy(this->agent);
	free(this);
}

/**
 * Described in header.
 */
imv_agent_if_t *imv_scanner_agent_create(const char *name, TNC_IMVID id,
										 TNC_Version *actual_version)
{
	private_imv_scanner_agent_t *this;
	imv_agent_t *agent;

	agent = imv_agent_create(name, msg_types, countof(msg_types), id,
							 actual_version);
	if (!agent)
	{
		return NULL;
	}
	
	INIT(this,
		.public = {
			.bind_functions = _bind_functions,
			.notify_connection_change = _notify_connection_change,
			.receive_message = _receive_message,
			.receive_message_long = _receive_message_long,
			.batch_ending = _batch_ending,
			.solicit_recommendation = _solicit_recommendation,
			.destroy = _destroy,
		},
		.agent = agent,
	);

	/* set the default port policy to closed (TRUE) or open (FALSE) */
	closed_port_policy = lib->settings->get_bool(lib->settings,
						"libimcv.plugins.imv-scanner.closed_port_policy", TRUE);
	DBG2(DBG_IMV, "default port policy is %s ports",
						closed_port_policy ? "closed" : "open");

	/* get the list of open|closed ports */
	tcp_ports = get_port_list("tcp");
	udp_ports = get_port_list("udp");

	return &this->public;
}

