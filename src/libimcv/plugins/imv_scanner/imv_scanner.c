/*
 * Copyright (C) 2011-2012 Andreas Steffen
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
#include <collections/linked_list.h>
#include <utils/lexparser.h>
#include <utils/debug.h>

/* IMV definitions */

static const char imv_name[] = "Scanner";

static pen_type_t msg_types[] = {
	{ PEN_IETF, PA_SUBTYPE_IETF_VPN }
};

static imv_agent_t *imv_scanner;

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


/*
 * see section 3.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imv_scanner = imv_agent_create(imv_name, msg_types, countof(msg_types),
								   imv_id, actual_version);
	if (!imv_scanner)
	{
		return TNC_RESULT_FATAL;
	}
	if (min_version > TNC_IFIMV_VERSION_1 || max_version < TNC_IFIMV_VERSION_1)
	{
		DBG1(DBG_IMV, "no common IF-IMV version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}

	/* set the default port policy to closed (TRUE) or open (FALSE) */
	closed_port_policy = lib->settings->get_bool(lib->settings,
						"libimcv.plugins.imv-scanner.closed_port_policy", TRUE);
	DBG2(DBG_IMV, "default port policy is %s ports",
						closed_port_policy ? "closed" : "open");

	/* get the list of open|closed ports */
	tcp_ports = get_port_list("tcp");
	udp_ports = get_port_list("udp");

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.8.2 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_NotifyConnectionChange(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imv_state_t *state;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_scanner_state_create(connection_id);
			return imv_scanner->create_state(imv_scanner, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imv_scanner->delete_state(imv_scanner, connection_id);
		default:
			return imv_scanner->change_state(imv_scanner, connection_id,
											 new_state, NULL);
	}
}

static TNC_Result receive_message(imv_state_t *state, imv_msg_t *in_msg)
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
			imv_scanner_state_t *imv_scanner_state;
			ietf_attr_port_filter_t *attr_port_filter;
			enumerator_t *enumerator;
			u_int8_t protocol;
			u_int16_t port;
			bool blocked, compliant = TRUE;


			imv_scanner_state = (imv_scanner_state_t*)state;
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
					imv_scanner_state->add_violating_port(imv_scanner_state,
														  strdup(buf));
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
	return imv_scanner->provide_recommendation(imv_scanner, state);
 }

/**
 * see section 3.8.4 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_ReceiveMessage(TNC_IMVID imv_id,
								  TNC_ConnectionID connection_id,
								  TNC_BufferReference msg,
								  TNC_UInt32 msg_len,
								  TNC_MessageType msg_type)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_scanner->get_state(imv_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	in_msg = imv_msg_create_from_data(imv_scanner, state, connection_id, msg_type,
									  chunk_create(msg, msg_len));
	result = receive_message(state, in_msg);
	in_msg->destroy(in_msg);

	return result;
}

/**
 * see section 3.8.6 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_ReceiveMessageLong(TNC_IMVID imv_id,
									  TNC_ConnectionID connection_id,
									  TNC_UInt32 msg_flags,
									  TNC_BufferReference msg,
									  TNC_UInt32 msg_len,
									  TNC_VendorID msg_vid,
									  TNC_MessageSubtype msg_subtype,
									  TNC_UInt32 src_imc_id,
									  TNC_UInt32 dst_imv_id)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_scanner->get_state(imv_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(imv_scanner, state, connection_id,
								src_imc_id, dst_imv_id, msg_vid, msg_subtype,
								chunk_create(msg, msg_len));
	result =receive_message(state, in_msg);
	in_msg->destroy(in_msg);

	return result;
}

/**
 * see section 3.8.7 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_SolicitRecommendation(TNC_IMVID imv_id,
										 TNC_ConnectionID connection_id)
{
	imv_state_t *state;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_scanner->get_state(imv_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return imv_scanner->provide_recommendation(imv_scanner, state);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	imv_state_t *state;
	imv_msg_t *out_msg;
	pa_tnc_attr_t *attr;
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	TNC_Result result = TNC_RESULT_SUCCESS;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_scanner->get_state(imv_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	state->get_recommendation(state, &rec, &eval);
	if (rec == TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION)
	{
		out_msg = imv_msg_create(imv_scanner, state, connection_id, imv_id,
								 TNC_IMCID_ANY, msg_types[0]);
		attr = ietf_attr_attr_request_create(PEN_IETF, IETF_ATTR_PORT_FILTER);
		out_msg->add_attribute(out_msg, attr);

		/* send PA-TNC message with excl flag not set */
		result = out_msg->send(out_msg, FALSE);
		out_msg->destroy(out_msg);

	}
	return result;
}

/**
 * see section 3.8.9 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Terminate(TNC_IMVID imv_id)
{
	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	tcp_ports->destroy_function(tcp_ports, free);
	udp_ports->destroy_function(udp_ports, free);
	imv_scanner->destroy(imv_scanner);
	imv_scanner = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_ProvideBindFunction(TNC_IMVID imv_id,
									   TNC_TNCS_BindFunctionPointer bind_function)
{
	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_scanner->bind_functions(imv_scanner, bind_function);
}
