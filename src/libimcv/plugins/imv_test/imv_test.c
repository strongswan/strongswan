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

#include "imv_test_state.h"

#include <imv/imv_agent.h>
#include <imv/imv_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_command.h>
#include <ita/ita_attr_dummy.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/debug.h>

/* IMV definitions */

static const char imv_name[] = "Test";

static pen_type_t msg_types[] = {
	{ PEN_ITA, PA_SUBTYPE_ITA_TEST }
};

static imv_agent_t *imv_test;

/**
 * see section 3.8.1 of TCG TNC IF-IMV Specification 1.3
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
	imv_test = imv_agent_create(imv_name, msg_types, countof(msg_types),
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
 * see section 3.8.2 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_NotifyConnectionChange(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imv_state_t *state;

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_test_state_create(connection_id);
			return imv_test->create_state(imv_test, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imv_test->delete_state(imv_test, connection_id);
		default:
			return imv_test->change_state(imv_test, connection_id,
										  new_state, NULL);
	}
}

static TNC_Result receive_message(imv_state_t *state, imv_msg_t *in_msg)
{
	imv_msg_t *out_msg;
	imv_test_state_t *test_state;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t attr_type;
	TNC_Result result;
	int rounds;
	bool fatal_error = FALSE, received_command = FALSE, retry = FALSE;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	/* add any new IMC and set its number of rounds */
	rounds = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imv-test.rounds", 0);
	test_state = (imv_test_state_t*)state;
	test_state->add_imc(test_state, in_msg->get_src_id(in_msg), rounds);

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		attr_type = attr->get_type(attr);

		if (attr_type.vendor_id != PEN_ITA)
		{
			continue;
		}
		if (attr_type.type == ITA_ATTR_COMMAND)
		{
			ita_attr_command_t *ita_attr;
			char *command;

			received_command = TRUE;
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
			else if (streq(command, "block") || streq(command, "none"))
			{
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);
			}
			else if (streq(command, "retry"))
			{
				retry = TRUE;
			}
			else
			{
				DBG1(DBG_IMV, "unsupported ITA Command '%s'", command);
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
			}
		}
		else if (attr_type.type == ITA_ATTR_DUMMY)
		{
			ita_attr_dummy_t *ita_attr;

			ita_attr = (ita_attr_dummy_t*)attr;
			DBG1(DBG_IMV, "received dummy attribute value (%d bytes)",
						   ita_attr->get_size(ita_attr));
		}
	}
	enumerator->destroy(enumerator);

	if (fatal_error)
	{
		state->set_recommendation(state,
							TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
							TNC_IMV_EVALUATION_RESULT_ERROR);
		out_msg = imv_msg_create_as_reply(in_msg);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}  
		return imv_test->provide_recommendation(imv_test, state);
	}

	/* request a handshake retry ? */
	if (retry)
	{
		test_state->set_rounds(test_state, rounds);
		return imv_test->request_handshake_retry(imv_test->get_id(imv_test),
											state->get_connection_id(state),
											TNC_RETRY_REASON_IMV_SERIOUS_EVENT);
	}

	/* repeat the measurement ? */
	if (test_state->another_round(test_state, in_msg->get_src_id(in_msg)))
	{
		out_msg = imv_msg_create_as_reply(in_msg);
		attr = ita_attr_command_create("repeat");
		out_msg->add_attribute(out_msg, attr);

		/* send PA-TNC message with excl flag set */
		result = out_msg->send(out_msg, TRUE);	
		out_msg->destroy(out_msg);

		return result;
	}

	if (received_command)
	{
		out_msg = imv_msg_create_as_reply(in_msg);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}  
		return imv_test->provide_recommendation(imv_test, state);
	}
	else
	{	
		return TNC_RESULT_SUCCESS;
	}
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

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_test->get_state(imv_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_data(imv_test, state, connection_id, msg_type,
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

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_test->get_state(imv_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(imv_test, state, connection_id,
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

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_test->get_state(imv_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return imv_test->provide_recommendation(imv_test, state);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
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
 * see section 3.8.9 of TCG TNC IF-IMV Specification 1.3
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
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.3
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
