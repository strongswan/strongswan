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

#include "imc_scanner_state.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_port_filter.h>
#include <ietf/ietf_attr_assess_result.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/lexparser.h>
#include <debug.h>

#include <stdio.h>

/* IMC definitions */

static const char imc_name[] = "Scanner";

#define IMC_VENDOR_ID	PEN_ITA
#define IMC_SUBTYPE		PA_SUBTYPE_ITA_SCANNER

static imc_agent_t *imc_scanner;

/**
 * see section 3.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_Initialize(TNC_IMCID imc_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has already been initialized", imc_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imc_scanner = imc_agent_create(imc_name, IMC_VENDOR_ID, IMC_SUBTYPE,
								imc_id, actual_version);
	if (!imc_scanner)
	{
		return TNC_RESULT_FATAL;
	}
	if (min_version > TNC_IFIMC_VERSION_1 || max_version < TNC_IFIMC_VERSION_1)
	{
		DBG1(DBG_IMC, "no common IF-IMC version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.8.2 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_NotifyConnectionChange(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imc_state_t *state;

	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imc_scanner_state_create(connection_id);
			return imc_scanner->create_state(imc_scanner, state);
		case TNC_CONNECTION_STATE_HANDSHAKE:
			if (imc_scanner->change_state(imc_scanner, connection_id, new_state,
				&state) != TNC_RESULT_SUCCESS)
			{
				return TNC_RESULT_FATAL;
			}
			state->set_result(state, imc_id,
							  TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			return TNC_RESULT_SUCCESS;
		case TNC_CONNECTION_STATE_DELETE:
			return imc_scanner->delete_state(imc_scanner, connection_id);
		default:
			return imc_scanner->change_state(imc_scanner, connection_id,
											 new_state, NULL);
	}
}

/**
 * Determine all TCP and UDP server sockets listening on physical interfaces
 */
static bool do_netstat(ietf_attr_port_filter_t *attr)
{
	FILE *file;
	char buf[BUF_LEN];
	chunk_t line, token;
	int n = 0;
	bool success = FALSE;
	const char loopback_v4[] = "127.0.0.1";
	const char loopback_v6[] = "::1";

	/* Open a pipe stream for reading the output of the netstat commmand */
	file = popen("/bin/netstat -n -l -p -4 -6 --inet", "r");
	if (!file)
	{
		DBG1(DBG_IMC, "Failed to run netstat command");
		return FALSE;
	}

	/* Read the output a line at a time */
	while (fgets(buf, BUF_LEN-1, file))
	{
		u_char *pos;
		u_int8_t new_protocol, protocol;
		u_int16_t new_port, port;
		int i;
		enumerator_t *enumerator;
		bool allowed, found = FALSE;

		DBG2(DBG_IMC, "%.*s", (int)(strlen(buf)-1), buf);

		if (n++ < 2)
		{
			/* skip the first two header lines */
			continue;
		}
		line = chunk_create(buf, strlen(buf));

		/* Extract the IP protocol type */
		if (!extract_token(&token, ' ', &line))
		{
			DBG1(DBG_IMC, "Protocol field in netstat output not found");
			goto end;
		}
		if (match("tcp", &token) || match("tcp6", &token))
		{
			new_protocol = IPPROTO_TCP;
		}
		else if (match("udp", &token) || match("udp6", &token))
		{
			new_protocol = IPPROTO_UDP;
		}
		else
		{
			DBG1(DBG_IMC, "Skipped unknown IP protocol in netstat output");
			continue;
		}

		/* Skip the Recv-Q and Send-Q fields */
		for (i = 0; i < 3; i++)
		{
			if (!eat_whitespace(&line) || !extract_token(&token, ' ', &line))
			{
				token = chunk_empty;
				break;
			}
		}
		if (token.len == 0)
		{
			DBG1(DBG_IMC, "Local Address field in netstat output not found");
			goto end;
		}

		/* Find the local port appended to the local address */
		pos = token.ptr + token.len;
		while (*--pos != ':' && --token.len);
		if (*pos != ':')
		{
			DBG1(DBG_IMC, "Local port field in netstat output not found");
			goto end;
		}
		token.len--;

		/* ignore ports of IPv4 and IPv6 loopback interfaces */
		if ((token.len == strlen(loopback_v4) &&
				memeq(loopback_v4, token.ptr, token.len)) ||
			(token.len == strlen(loopback_v6) &&
				memeq(loopback_v6, token.ptr, token.len)))
		{
			continue;
		}

		/* convert the port string to an integer */
		new_port = atoi(pos+1);

		/* check if the there is already a port entry */
		enumerator = attr->create_port_enumerator(attr);
		while (enumerator->enumerate(enumerator, &allowed, &protocol, &port))
		{
			if (new_port == port && new_protocol == protocol)
			{
				found = TRUE;
			}
		}
		enumerator->destroy(enumerator);

		/* Skip the duplicate port entry */
		if (found)
		{
			continue;
		}

		/* Add new port entry */
		attr->add_port(attr, FALSE, new_protocol, new_port);
	}

	/* Successfully completed the parsing of the netstat output */
	success = TRUE;

end:
	/* Close the pipe stream */
	pclose(file);
	return success;
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	linked_list_t *attr_list;
	pa_tnc_attr_t *attr;
	ietf_attr_port_filter_t *attr_port_filter;
	TNC_Result result;

	attr = ietf_attr_port_filter_create();
	attr->set_noskip_flag(attr, TRUE);
	attr_port_filter = (ietf_attr_port_filter_t*)attr;
	if (!do_netstat(attr_port_filter))
	{
		attr->destroy(attr);
		return TNC_RESULT_FATAL;
	}
	attr_list = linked_list_create();
	attr_list->insert_last(attr_list, attr);
	result = imc_scanner->send_message(imc_scanner, connection_id, FALSE, 0,
									   TNC_IMVID_ANY, attr_list);
	attr_list->destroy(attr_list);

	return result;
}

/**
 * see section 3.8.3 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return send_message(connection_id);
}

static TNC_Result receive_message(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id,
								  TNC_UInt32 msg_flags,
								  chunk_t msg,
								  TNC_VendorID msg_vid,
								  TNC_MessageSubtype msg_subtype,
								  TNC_UInt32 src_imv_id,
								  TNC_UInt32 dst_imc_id)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	pen_type_t attr_type;
	imc_state_t *state;
	enumerator_t *enumerator;
	TNC_Result result;
	TNC_UInt32 target_imc_id;
	bool fatal_error;

	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_scanner->get_state(imc_scanner, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	/* parse received PA-TNC message and automatically handle any errors */
	result = imc_scanner->receive_message(imc_scanner, state, msg, msg_vid,
							msg_subtype, src_imv_id, dst_imc_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}
	target_imc_id = (dst_imc_id == TNC_IMCID_ANY) ? imc_id : dst_imc_id;

	/* preprocess any IETF standard error attributes */
	fatal_error = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg);

	/* analyze PA-TNC attributes */
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		attr_type = attr->get_type(attr);

		if (attr_type.vendor_id == PEN_IETF &&
			attr_type.type == IETF_ATTR_ASSESSMENT_RESULT)
		{
			ietf_attr_assess_result_t *ietf_attr;

			ietf_attr = (ietf_attr_assess_result_t*)attr;
			state->set_result(state, target_imc_id,
							  ietf_attr->get_result(ietf_attr));
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		return TNC_RESULT_FATAL;
	}

	/* if no assessment result is known then repeat the measurement */
	return state->get_result(state, target_imc_id, NULL) ?
		   TNC_RESULT_SUCCESS : send_message(connection_id);
}

/**
 * see section 3.8.4 of TCG TNC IF-IMC Specification 1.3

 */
TNC_Result TNC_IMC_ReceiveMessage(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id,
								  TNC_BufferReference msg,
								  TNC_UInt32 msg_len,
								  TNC_MessageType msg_type)
{
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = msg_type >> 8;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	return receive_message(imc_id, connection_id, 0, chunk_create(msg, msg_len),
						   msg_vid,	msg_subtype, 0, TNC_IMCID_ANY);
}

/**
 * see section 3.8.6 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMC_ReceiveMessageLong(TNC_IMCID imc_id,
									  TNC_ConnectionID connection_id,
									  TNC_UInt32 msg_flags,
									  TNC_BufferReference msg,
									  TNC_UInt32 msg_len,
									  TNC_VendorID msg_vid,
									  TNC_MessageSubtype msg_subtype,
									  TNC_UInt32 src_imv_id,
									  TNC_UInt32 dst_imc_id)
{
	return receive_message(imc_id, connection_id, msg_flags,
						   chunk_create(msg, msg_len), msg_vid, msg_subtype,
						   src_imv_id, dst_imc_id);
}

/**
 * see section 3.8.7 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BatchEnding(TNC_IMCID imc_id,
							   TNC_ConnectionID connection_id)
{
	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.8.8 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_Terminate(TNC_IMCID imc_id)
{
	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imc_scanner->destroy(imc_scanner);
	imc_scanner = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_ProvideBindFunction(TNC_IMCID imc_id,
									   TNC_TNCC_BindFunctionPointer bind_function)
{
	if (!imc_scanner)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imc_scanner->bind_functions(imc_scanner, bind_function);
}
