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

#include "imc_test_state.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_assess_result.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_command.h>
#include <ita/ita_attr_dummy.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>

/* IMC definitions */

static const char imc_name[] = "Test";

#define IMC_VENDOR_ID	PEN_ITA
#define IMC_SUBTYPE		PA_SUBTYPE_ITA_TEST

static imc_agent_t *imc_test;
 
/**
 * see section 3.8.1 of TCG TNC IF-IMC Specification 1.3
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
 * see section 3.8.2 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_NotifyConnectionChange(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imc_state_t *state;
	imc_test_state_t *test_state;
	TNC_Result result;
	TNC_UInt32 additional_id;
	char *command;
	bool retry;
	void *pointer;
	enumerator_t *enumerator;
	int dummy_size, additional_ids;

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
			dummy_size = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imc-test.dummy_size", 0);
			retry = lib->settings->get_bool(lib->settings,
								"libimcv.plugins.imc-test.retry", FALSE);
			state = imc_test_state_create(connection_id, command, dummy_size,
										  retry);

			result = imc_test->create_state(imc_test, state);
			if (result != TNC_RESULT_SUCCESS)
			{
				return result;
			}

			/* Optionally reserve additional IMC IDs */
			additional_ids = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imc-test.additional_ids", 0);
			imc_test->reserve_additional_ids(imc_test, additional_ids -
								imc_test->count_additional_ids(imc_test));

			return TNC_RESULT_SUCCESS;

		case TNC_CONNECTION_STATE_HANDSHAKE:
			/* get updated IMC state */
			result = imc_test->change_state(imc_test, connection_id,
											new_state, &state);
			if (result != TNC_RESULT_SUCCESS)
			{
				return TNC_RESULT_FATAL;
			}
			test_state = (imc_test_state_t*)state;

			/* is it the first handshake or a retry ? */
			if (!test_state->is_first_handshake(test_state))
			{
				command = lib->settings->get_str(lib->settings,
								"libimcv.plugins.imc-test.retry_command",
								test_state->get_command(test_state));
				test_state->set_command(test_state, command);
			}

			state->set_result(state, imc_id, TNC_IMV_EVALUATION_RESULT_DONT_KNOW);

			/* Exit if there are no additional IMC IDs */
			if (!imc_test->count_additional_ids(imc_test))
			{
				return result;
			}

			enumerator = imc_test->create_id_enumerator(imc_test);
			while (enumerator->enumerate(enumerator, &pointer))
			{
				/* interpret pointer as scalar value */
				additional_id = (TNC_UInt32)pointer;

				state->set_result(state, additional_id,
								  TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			}
			enumerator->destroy(enumerator);

			return TNC_RESULT_SUCCESS;

		case TNC_CONNECTION_STATE_DELETE:
			return imc_test->delete_state(imc_test, connection_id);

		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
			/* get updated IMC state */
			result = imc_test->change_state(imc_test, connection_id,
											new_state, &state);
			if (result != TNC_RESULT_SUCCESS)
			{
				return TNC_RESULT_FATAL;
			}
			test_state = (imc_test_state_t*)state;

			/* do a handshake retry? */
			if (test_state->do_handshake_retry(test_state))
			{
				return imc_test->request_handshake_retry(imc_id, connection_id,
									TNC_RETRY_REASON_IMC_REMEDIATION_COMPLETE);
			}
			return TNC_RESULT_SUCCESS;

		default:
			return imc_test->change_state(imc_test, connection_id,
										  new_state, NULL);
	}
}

static TNC_Result send_message(imc_state_t *state, TNC_UInt32 src_imc_id,
												   TNC_UInt32 dst_imv_id)
{
	imc_test_state_t *test_state;
	linked_list_t *attr_list;
	pa_tnc_attr_t *attr;
	bool excl;
	TNC_ConnectionID connection_id;
	TNC_Result result;

	attr_list = linked_list_create();
	connection_id = state->get_connection_id(state);
	test_state = (imc_test_state_t*)state;

	if (test_state->get_dummy_size(test_state))
	{
		attr = ita_attr_dummy_create(test_state->get_dummy_size(test_state));
		attr->set_noskip_flag(attr, TRUE);
		attr_list->insert_last(attr_list, attr);
	}
	attr = ita_attr_command_create(test_state->get_command(test_state));
	attr->set_noskip_flag(attr, TRUE);
	attr_list->insert_last(attr_list, attr);

	excl = dst_imv_id != TNC_IMVID_ANY;
	result = imc_test->send_message(imc_test, connection_id, excl, src_imc_id,
									dst_imv_id, attr_list);
	attr_list->destroy(attr_list);

	return result;
}

/**
 * see section 3.8.3 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	imc_state_t *state;
	enumerator_t *enumerator;
	void *pointer;
	TNC_UInt32 additional_id;
	TNC_Result result;

	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_test->get_state(imc_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	/* send PA message for primary IMC ID */
	result = send_message(state, imc_id, TNC_IMVID_ANY);

	/* Exit if there are no additional IMC IDs */
	if (!imc_test->count_additional_ids(imc_test))
	{
		return result;
	}

	/* Do we have support for transporting multiple IMC IDs? */
	if (!state->has_long(state))
	{
		DBG1(DBG_IMC, "IMC %u \"%s\" did not detect support for transporting "
					  "multiple IMC IDs", imc_id, imc_name);
		return result;
	}

	/* send PA messages for additional IMC IDs */
	enumerator = imc_test->create_id_enumerator(imc_test);
	while (result == TNC_RESULT_SUCCESS &&
		   enumerator->enumerate(enumerator, &pointer))
	{
		/* interpret pointer as scalar value */
		additional_id = (TNC_UInt32)pointer;
		result = send_message(state, additional_id, TNC_IMVID_ANY);	
	}
	enumerator->destroy(enumerator);

	return result;
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
	bool fatal_error = FALSE;

	if (!imc_test)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_test->get_state(imc_test, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imc_test->receive_message(imc_test, state, msg, msg_vid,
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

		if (attr_type.vendor_id == PEN_IETF)
		{
			ietf_attr_assess_result_t *ietf_attr;

			ietf_attr = (ietf_attr_assess_result_t*)attr;
			state->set_result(state, target_imc_id,
							  ietf_attr->get_result(ietf_attr));
		}
		else if (attr_type.vendor_id == PEN_ITA)
		{
			if (attr_type.type == ITA_ATTR_COMMAND)
			{
				ita_attr_command_t *ita_attr;

				ita_attr = (ita_attr_command_t*)attr;
				DBG1(DBG_IMC, "received command '%s'",
					 ita_attr->get_command(ita_attr));
			}
			else if (attr_type.type == ITA_ATTR_DUMMY)
			{
				ita_attr_dummy_t *ita_attr;

				ita_attr = (ita_attr_dummy_t*)attr;
				DBG1(DBG_IMC, "received dummy attribute value (%d bytes)",
					 ita_attr->get_size(ita_attr));
			}
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
		   TNC_RESULT_SUCCESS : send_message(state, dst_imc_id, src_imv_id);
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
	if (!imc_test)
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
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.3
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
