/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_port_filter.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/linked_list.h>
#include <utils/lexparser.h>
#include <debug.h>

/* IMV definitions */

static const char imv_name[] = "Scanner";

#define IMV_VENDOR_ID	PEN_ITA
#define IMV_SUBTYPE		PA_SUBTYPE_ITA_SCANNER

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
	imv_scanner = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
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

static TNC_Result receive_message(TNC_IMVID imv_id,
								  TNC_ConnectionID connection_id,
								  TNC_UInt32 msg_flags,
								  chunk_t msg,
								  TNC_VendorID msg_vid,
								  TNC_MessageSubtype msg_subtype,
								  TNC_UInt32 src_imc_id,
								  TNC_UInt32 dst_imv_id)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	imv_state_t *state;
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error;

	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMV state */
	if (!imv_scanner->get_state(imv_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imv_scanner->receive_message(imv_scanner, state, msg, msg_vid,
					 		msg_subtype, src_imc_id, dst_imv_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}

	/* preprocess any IETF standard error attributes */
	fatal_error = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg);

	/* analyze PA-TNC attributes */
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->get_vendor_id(attr) == PEN_IETF &&
			attr->get_type(attr) == IETF_ATTR_PORT_FILTER)
		{
			ietf_attr_port_filter_t *attr_port_filter;
			enumerator_t *enumerator;
			u_int8_t protocol;
			u_int16_t port;
			char buf[BUF_LEN], *pos = buf;
			size_t len = BUF_LEN;
			bool blocked, compliant = TRUE;
	
			attr_port_filter = (ietf_attr_port_filter_t*)attr;
			enumerator = attr_port_filter->create_port_enumerator(attr_port_filter);
			while (enumerator->enumerate(enumerator, &blocked, &protocol, &port))
			{
				enumerator_t *e;
				port_range_t *port_range;
				bool passed, found = FALSE;
				int written = 0;

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
					written = snprintf(pos, len, " %s/%u",
									  (protocol == IPPROTO_TCP) ? "tcp" : "udp",
									   port);
					if (written < 0 || written >= len)
					{
						break;
					}
					pos += written;
					len -= written;
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
				imv_scanner_state_t *imv_scanner_state;

				imv_scanner_state = (imv_scanner_state_t*)state;
				imv_scanner_state->set_violating_ports(imv_scanner_state, buf);
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);	
			}		  
		}		
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);			  
		return imv_scanner->provide_recommendation(imv_scanner, connection_id);
	}

	return imv_scanner->provide_recommendation(imv_scanner, connection_id);
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
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = msg_type >> 8;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	return receive_message(imv_id, connection_id, 0, chunk_create(msg, msg_len),
						   msg_vid,	msg_subtype, 0, TNC_IMVID_ANY);
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
	return receive_message(imv_id, connection_id, msg_flags,
						   chunk_create(msg, msg_len), msg_vid, msg_subtype,
						   src_imc_id, dst_imv_id);
}

/**
 * see section 3.8.7 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_SolicitRecommendation(TNC_IMVID imv_id,
										 TNC_ConnectionID connection_id)
{
	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_scanner->provide_recommendation(imv_scanner, connection_id);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return TNC_RESULT_SUCCESS;
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
