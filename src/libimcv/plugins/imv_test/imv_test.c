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
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_command.h>
#include <ita/ita_attr_dummy.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>

/* IMV definitions */

static const char imv_name[] = "Test";

#define IMV_VENDOR_ID	PEN_ITA
#define IMV_SUBTYPE		PA_SUBTYPE_ITA_TEST

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
	pen_type_t attr_type;
	linked_list_t *attr_list;
	imv_state_t *state;
	imv_test_state_t *test_state;
	enumerator_t *enumerator;
	TNC_Result result;
	int rounds;
	bool fatal_error, received_command = FALSE, retry = FALSE;

	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMV state */
	if (!imv_test->get_state(imv_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	test_state = (imv_test_state_t*)state;

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imv_test->receive_message(imv_test, state, msg, msg_vid,
					 		msg_subtype, src_imc_id, dst_imv_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}

	/* preprocess any IETF standard error attributes */
	fatal_error = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg);

	/* add any new IMC and set its number of rounds */
	rounds = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imv-test.rounds", 0);
	test_state->add_imc(test_state, src_imc_id, rounds);

	/* analyze PA-TNC attributes */
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
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
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);			  
		return imv_test->provide_recommendation(imv_test, connection_id,
												src_imc_id);
	}

	/* request a handshake retry ? */
	if (retry)
	{
		test_state->set_rounds(test_state, rounds);
		return imv_test->request_handshake_retry(imv_id, connection_id,
								TNC_RETRY_REASON_IMV_SERIOUS_EVENT);
	}
	
	/* repeat the measurement ? */
	if (test_state->another_round(test_state, src_imc_id))
	{
		attr_list = linked_list_create();
		attr = ita_attr_command_create("repeat");
		attr_list->insert_last(attr_list, attr);
		result = imv_test->send_message(imv_test, connection_id, TRUE, imv_id,
							src_imc_id, attr_list);	
		attr_list->destroy(attr_list);

		return result;
	}

	return received_command ? imv_test->provide_recommendation(imv_test,
			 connection_id, src_imc_id) : TNC_RESULT_SUCCESS;
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
	if (!imv_test)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_test->provide_recommendation(imv_test, connection_id,
											TNC_IMCID_ANY);
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
