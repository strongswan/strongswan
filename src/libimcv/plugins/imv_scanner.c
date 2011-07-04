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
#include <debug.h>

/* IMV definitions */

static const char imv_name[] = "Scanner";

#define IMV_VENDOR_ID	PEN_ITA
#define IMV_SUBTYPE		PA_SUBTYPE_ITA_SCANNER

static imv_agent_t *imv_scanner;

/**
 * see section 3.7.1 of TCG TNC IF-IMV Specification 1.2
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
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.7.2 of TCG TNC IF-IMV Specification 1.2
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

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *attr;
	TNC_Result result;

	msg = pa_tnc_msg_create();
	msg->build(msg);
	result = imv_scanner->send_message(imv_scanner, connection_id,
									msg->get_encoding(msg));	
	msg->destroy(msg);

	return result;
}

/**
 * see section 3.7.3 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_ReceiveMessage(TNC_IMVID imv_id,
								  TNC_ConnectionID connection_id,
								  TNC_BufferReference msg,
								  TNC_UInt32 msg_len,
								  TNC_MessageType msg_type)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	imv_state_t *state;
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error = FALSE;

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
	result = imv_scanner->receive_message(imv_scanner, connection_id,
									   chunk_create(msg, msg_len), msg_type,
									   &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}

	/* analyze PA-TNC attributes */
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->get_vendor_id(attr) != PEN_IETF)
		{
			continue;
		}

		if (attr->get_type(attr) == IETF_ATTR_PA_TNC_ERROR)
		{
			ietf_attr_pa_tnc_error_t *error_attr;
			pa_tnc_error_code_t error_code;
			chunk_t msg_info, attr_info;

			error_attr = (ietf_attr_pa_tnc_error_t*)attr;
			error_code = error_attr->get_error_code(error_attr);
			msg_info = error_attr->get_msg_info(error_attr);

			DBG1(DBG_IMV, "received PA-TNC error '%N' concerning message %#B",
				 pa_tnc_error_code_names, error_code, &msg_info);
			switch (error_code)
			{
				case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
					attr_info = error_attr->get_attr_info(error_attr);
					DBG1(DBG_IMV, "  unsupported attribute %#B", &attr_info);
					break;
				default:
					break;
			}
			fatal_error = TRUE;
		}
		else if (attr->get_type(attr) == IETF_ATTR_PORT_FILTER)
		{
			ietf_attr_port_filter_t *attr_port_filter;
			enumerator_t *enumerator;
			bool blocked;
			u_int8_t protocol;
			u_int16_t port;
	
			attr_port_filter = (ietf_attr_port_filter_t*)attr;
			enumerator = attr_port_filter->create_port_enumerator(attr_port_filter);
			while (enumerator->enumerate(enumerator, &blocked, &protocol, &port))
			{
				DBG2(DBG_IMV, "%s: %s %5u", blocked ? "blocked" : "allowed",
					(protocol == IPPROTO_TCP) ? "tcp" : "udp", port);
			}
			enumerator->destroy(enumerator);
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
 * see section 3.7.4 of TCG TNC IF-IMV Specification 1.2
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
 * see section 3.7.5 of TCG TNC IF-IMV Specification 1.2
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
 * see section 3.7.6 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_Terminate(TNC_IMVID imv_id)
{
	if (!imv_scanner)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imv_scanner->destroy(imv_scanner);
	imv_scanner = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.2
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
