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

#include "imv_test_state.h"

#include <imv/imv_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ita/ita_attr_command.h>

#include <pen/pen.h>

#include <debug.h>

/* IMV definitions */

static const char imv_name[] = "Test";

#define IMV_VENDOR_ID	PEN_ITA
#define IMV_SUBTYPE		0x01

static imv_agent_t *imv_test;

/**
 * see section 3.7.1 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imv_test = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
								imv_id, actual_version);
	if (!imv_test)
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
	int rounds;

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			rounds = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imv-test.rounds", 0);
			state = imv_test_state_create(connection_id, rounds);
			return imv_test->create_state(imv_test, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imv_test->delete_state(imv_test, connection_id);
		default:
			return imv_test->change_state(imv_test, connection_id, new_state);
	}
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *attr;
	TNC_Result result;

	attr = ita_attr_command_create("repeat");
	msg = pa_tnc_msg_create();
	msg->add_attribute(msg, attr);
	msg->build(msg);
	result = imv_test->send_message(imv_test, connection_id,
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
	imv_test_state_t *imv_test_state;
	TNC_Result result = TNC_RESULT_SUCCESS;
	enumerator_t *enumerator;

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* process received message */
	DBG2(DBG_IMV, "IMV %u \"%s\" received message type 0x%08x for Connection ID %u",
				   imv_id, imv_name, msg_type, connection_id);
	pa_tnc_msg = pa_tnc_msg_create_from_data(chunk_create(msg, msg_len));

	if (pa_tnc_msg->process(pa_tnc_msg) != SUCCESS)
	{
 		pa_tnc_msg->destroy(pa_tnc_msg);
		return TNC_RESULT_FATAL;
	}

	/* get current IMV state */
	if (!imv_test->get_state(imv_test, connection_id, &state))
	{
		pa_tnc_msg->destroy(pa_tnc_msg);
		return TNC_RESULT_FATAL;
	}

	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->get_vendor_id(attr) == PEN_ITA &&
			attr->get_type(attr) == ITA_ATTR_COMMAND)
		{
			ita_attr_command_t *ita_attr;
			char *command;
	
			ita_attr = (ita_attr_command_t*)attr;
			command = ita_attr->get_command(ita_attr);

			if (streq(command, "allow"))
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_COMPLIANT);			  
			}
			else if (streq(command, "isolate"))
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR);			  
			}
			else if (streq(command, "none"))
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);			  
			}
			else
			{
				result = TNC_RESULT_FATAL;
			}
			break;
		}		
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	/* repeat the measurement ? */
	imv_test_state = (imv_test_state_t*)state;
	if (imv_test_state->another_round(imv_test_state))
	{
		return send_message(connection_id);
	}

	return imv_test->provide_recommendation(imv_test, connection_id);
}

/**
 * see section 3.7.4 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_SolicitRecommendation(TNC_IMVID imv_id,
										 TNC_ConnectionID connection_id)
{
	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_test->provide_recommendation(imv_test, connection_id);
}

/**
 * see section 3.7.5 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	if (!imv_test)
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
	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imv_test->destroy(imv_test);
	imv_test = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_ProvideBindFunction(TNC_IMVID imv_id,
									   TNC_TNCS_BindFunctionPointer bind_function)
{
	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_test->bind_functions(imv_test, bind_function);
}
