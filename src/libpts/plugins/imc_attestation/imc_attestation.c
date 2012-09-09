/*
 * Copyright (C) 2011-2012 Sansar Choinyambuu, Andreas Steffen
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

#include "imc_attestation_state.h"
#include "imc_attestation_process.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_assess_result.h>

#include <libpts.h>

#include <pts/pts_error.h>

#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_meas_algo.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>
#include <utils/linked_list.h>

/* IMC definitions */

static const char imc_name[] = "Attestation";

#define IMC_VENDOR_ID				PEN_TCG
#define IMC_SUBTYPE					PA_SUBTYPE_TCG_PTS

static imc_agent_t *imc_attestation;

/**
 * Supported PTS measurement algorithms
 */
static pts_meas_algorithms_t supported_algorithms = PTS_MEAS_ALGO_NONE;

/**
 * Supported PTS Diffie Hellman Groups
 */
static pts_dh_group_t supported_dh_groups = PTS_DH_GROUP_NONE;

/**
 * see section 3.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_Initialize(TNC_IMCID imc_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has already been initialized", imc_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	if (!pts_meas_algo_probe(&supported_algorithms) ||
		!pts_dh_group_probe(&supported_dh_groups))
	{
		return TNC_RESULT_FATAL;
	}
	imc_attestation = imc_agent_create(imc_name, IMC_VENDOR_ID, IMC_SUBTYPE,
									   imc_id, actual_version);
	if (!imc_attestation)
	{
		return TNC_RESULT_FATAL;
	}

	libpts_init();
	
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

	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imc_attestation_state_create(connection_id);
			return imc_attestation->create_state(imc_attestation, state);
		case TNC_CONNECTION_STATE_HANDSHAKE:
			if (imc_attestation->change_state(imc_attestation, connection_id,
				new_state, &state) != TNC_RESULT_SUCCESS)
			{
				return TNC_RESULT_FATAL;
			}
			state->set_result(state, imc_id,
							  TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			return TNC_RESULT_SUCCESS;
		case TNC_CONNECTION_STATE_DELETE:
			return imc_attestation->delete_state(imc_attestation, connection_id);
		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
		default:
			return imc_attestation->change_state(imc_attestation, connection_id,
												  new_state, NULL);
	}
}


/**
 * see section 3.8.3 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	imc_state_t *state;
	imc_attestation_state_t *attestation_state;
	pts_t *pts;
	char *platform_info;
	TNC_Result result = TNC_RESULT_SUCCESS;

	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_attestation->get_state(imc_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imc_attestation_state_t*)state;
	pts = attestation_state->get_pts(attestation_state);

	platform_info = pts->get_platform_info(pts);
	if (platform_info)
	{
		linked_list_t *attr_list;
		pa_tnc_attr_t *attr;

		attr_list = linked_list_create();
		attr = ietf_attr_product_info_create(0, 0, platform_info);
		attr_list->insert_last(attr_list, attr);
		result = imc_attestation->send_message(imc_attestation, connection_id,
										FALSE, 0, TNC_IMVID_ANY, attr_list);
		attr_list->destroy(attr_list);
	}

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
	pen_type_t type;
	linked_list_t *attr_list;
	imc_state_t *state;
	imc_attestation_state_t *attestation_state;
	enumerator_t *enumerator;
	TNC_Result result;
	TNC_UInt32 target_imc_id;

	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_attestation->get_state(imc_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imc_attestation_state_t*)state;

	/* parse received PA-TNC message and automatically handle any errors */
	result = imc_attestation->receive_message(imc_attestation, state, msg,
					msg_vid, msg_subtype, src_imv_id, dst_imc_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}
	target_imc_id = (dst_imc_id == TNC_IMCID_ANY) ? imc_id : dst_imc_id;
	
	/* preprocess any IETF standard error attributes */
	result = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg) ?
					TNC_RESULT_FATAL : TNC_RESULT_SUCCESS;

	attr_list = linked_list_create();

	/* analyze PA-TNC attributes */
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF)
		{
			if (type.type == IETF_ATTR_PA_TNC_ERROR)
			{
				ietf_attr_pa_tnc_error_t *error_attr;
				pen_type_t error_code;
				chunk_t msg_info;

				error_attr = (ietf_attr_pa_tnc_error_t*)attr;
				error_code = error_attr->get_error_code(error_attr);

				if (error_code.vendor_id == PEN_TCG)
				{
					msg_info = error_attr->get_msg_info(error_attr);

					DBG1(DBG_IMC, "received TCG-PTS error '%N'",
						 pts_error_code_names, error_code.type);
					DBG1(DBG_IMC, "error information: %B", &msg_info);

					result = TNC_RESULT_FATAL;
				}
			}
			else if (type.type == IETF_ATTR_ASSESSMENT_RESULT)
			{
				ietf_attr_assess_result_t *ietf_attr;

				ietf_attr = (ietf_attr_assess_result_t*)attr;
				state->set_result(state, target_imc_id,
								  ietf_attr->get_result(ietf_attr));
			}
		}
		else if (type.vendor_id == PEN_TCG)
		{
			if (!imc_attestation_process(attr, attr_list, attestation_state,
				supported_algorithms, supported_dh_groups))
			{
				result = TNC_RESULT_FATAL;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (result == TNC_RESULT_SUCCESS && attr_list->get_count(attr_list))
	{
		result = imc_attestation->send_message(imc_attestation, connection_id,
										FALSE, 0, TNC_IMVID_ANY, attr_list);
	}
	attr_list->destroy(attr_list);

	return result;
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
	if (!imc_attestation)
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
	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	libpts_deinit();

	imc_attestation->destroy(imc_attestation);
	imc_attestation = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_ProvideBindFunction(TNC_IMCID imc_id,
								TNC_TNCC_BindFunctionPointer bind_function)
{
	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imc_attestation->bind_functions(imc_attestation, bind_function);
}
