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

#include "imc_test_state.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ita/ita_attr_command.h>

#include <pen/pen.h>

#include <debug.h>

/* IMC definitions */

static const char imc_name[] = "Test";

#define IMC_VENDOR_ID	PEN_ITA
#define IMC_SUBTYPE		0x01

static imc_agent_t *imc_test;
 
/**
 * see section 3.7.1 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_Initialize(TNC_IMCID imc_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has already been initialized", imc_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imc_test = imc_agent_create(imc_name, IMC_VENDOR_ID, IMC_SUBTYPE,
								imc_id, actual_version);
	if (!imc_test)
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
 * see section 3.7.2 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_NotifyConnectionChange(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imc_state_t *state;
	imc_test_state_t *test_state;
	char *command;
	bool retry;

	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			command = lib->settings->get_str(lib->settings,
						 "libimcv.plugins.imc-test.command", "none");
			retry = lib->settings->get_bool(lib->settings,
								"libimcv.plugins.imc-test.retry", FALSE);
			state = imc_test_state_create(connection_id, command, retry);
			return imc_test->create_state(imc_test, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imc_test->delete_state(imc_test, connection_id);
		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
			/* get current IMC state and update it */
			if (!imc_test->get_state(imc_test, connection_id, &state))
			{
				return TNC_RESULT_FATAL;
			}
			state->change_state(state, new_state);
			test_state = (imc_test_state_t*)state;

			/* do a handshake retry? */
			if (test_state->do_handshake_retry(test_state))
			{
				command = lib->settings->get_str(lib->settings,
								"libimcv.plugins.imc-test.retry_command",
								test_state->get_command(test_state));
				test_state->set_command(test_state, command);
				return imc_test->request_handshake_retry(imc_id, connection_id,
									TNC_RETRY_REASON_IMC_REMEDIATION_COMPLETE);
			}
			return TNC_RESULT_SUCCESS;
		default:
			return imc_test->change_state(imc_test, connection_id, new_state);
	}
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *attr;
	imc_state_t *state;
	imc_test_state_t *test_state;
	TNC_Result result;

	if (!imc_test->get_state(imc_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	test_state = (imc_test_state_t*)state;
	attr = ita_attr_command_create(test_state->get_command(test_state));
	attr->set_noskip_flag(attr, TRUE);
	msg = pa_tnc_msg_create();
	msg->add_attribute(msg, attr);
	msg->build(msg);
	result = imc_test->send_message(imc_test, connection_id,
									msg->get_encoding(msg));	
	msg->destroy(msg);

	return result;
}

/**
 * see section 3.7.3 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return send_message(connection_id);
}

/**
 * see section 3.7.4 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_ReceiveMessage(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id,
								  TNC_BufferReference msg,
								  TNC_UInt32 msg_len,
								  TNC_MessageType msg_type)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error = FALSE;

	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imc_test->receive_message(imc_test, connection_id,
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
		if (attr->get_vendor_id(attr) == PEN_IETF &&
			attr->get_type(attr) == IETF_ATTR_PA_TNC_ERROR)
		{
			ietf_attr_pa_tnc_error_t *error_attr;
			pa_tnc_error_code_t error_code;
			chunk_t msg_info, attr_info;

			error_attr = (ietf_attr_pa_tnc_error_t*)attr;
			error_code = error_attr->get_error_code(error_attr);
			msg_info = error_attr->get_msg_info(error_attr);

			DBG1(DBG_IMC, "received PA-TNC error '%N' concerning message %#B",
				 pa_tnc_error_code_names, error_code, &msg_info);
			switch (error_code)
			{
				case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
					attr_info = error_attr->get_attr_info(error_attr);
					DBG1(DBG_IMC, "  unsupported attribute %#B", &attr_info);
					break;
				default:
					break;
			}
			fatal_error = TRUE;
		}
		else if (attr->get_vendor_id(attr) == PEN_ITA &&
				 attr->get_type(attr) == ITA_ATTR_COMMAND)
		{
			ita_attr_command_t *ita_attr;
			char *command;
	
			ita_attr = (ita_attr_command_t*)attr;
			command = ita_attr->get_command(ita_attr);
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	/* if no error occurred then always return the same response */
	return fatal_error ? TNC_RESULT_FATAL : send_message(connection_id);
}

/**
 * see section 3.7.5 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_BatchEnding(TNC_IMCID imc_id,
							   TNC_ConnectionID connection_id)
{
	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.7.6 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_Terminate(TNC_IMCID imc_id)
{
	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imc_test->destroy(imc_test);
	imc_test = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_ProvideBindFunction(TNC_IMCID imc_id,
									   TNC_TNCC_BindFunctionPointer bind_function)
{
	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imc_test->bind_functions(imc_test, bind_function);
}
