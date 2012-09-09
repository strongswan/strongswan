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

#include "imv_attestation_state.h"
#include "imv_attestation_process.h"
#include "imv_attestation_build.h"

#include <imv/imv_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>

#include <libpts.h>

#include <pts/pts.h>
#include <pts/pts_database.h>
#include <pts/pts_creds.h>

#include <tcg/tcg_attr.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>
#include <credentials/credential_manager.h>
#include <utils/linked_list.h>

/* IMV definitions */

static const char imv_name[] = "Attestation";

#define IMV_VENDOR_ID			PEN_TCG
#define IMV_SUBTYPE				PA_SUBTYPE_TCG_PTS

static imv_agent_t *imv_attestation;

/**
 * Supported PTS measurement algorithms
 */
static pts_meas_algorithms_t supported_algorithms = PTS_MEAS_ALGO_NONE;

/**
 * Supported PTS Diffie Hellman Groups
 */
static pts_dh_group_t supported_dh_groups = PTS_DH_GROUP_NONE;

/**
 * PTS file measurement database
 */
static pts_database_t *pts_db;

/**
 * PTS credentials
 */
static pts_creds_t *pts_creds;

/**
 * PTS credential manager
 */
static credential_manager_t *pts_credmgr;

/**
 * see section 3.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	char *hash_alg, *dh_group, *uri, *cadir;

	if (imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	if (!pts_meas_algo_probe(&supported_algorithms) ||
		!pts_dh_group_probe(&supported_dh_groups))
	{
		return TNC_RESULT_FATAL;
	}
	imv_attestation = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
									   imv_id, actual_version);
	if (!imv_attestation)
	{
		return TNC_RESULT_FATAL;
	}

	libpts_init();
	
	if (min_version > TNC_IFIMV_VERSION_1 || max_version < TNC_IFIMV_VERSION_1)
	{
		DBG1(DBG_IMV, "no common IF-IMV version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}

	hash_alg = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.hash_algorithm", "sha256");
	dh_group = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.dh_group", "ecp256");

	if (!pts_meas_algo_update(hash_alg, &supported_algorithms) ||
		!pts_dh_group_update(dh_group, &supported_dh_groups))
	{
		return TNC_RESULT_FATAL;
	}

	/* create a PTS credential manager */
	pts_credmgr = credential_manager_create();

	/* create PTS credential set */
	cadir = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.cadir", NULL);
	pts_creds = pts_creds_create(cadir);
	if (pts_creds)
	{
		pts_credmgr->add_set(pts_credmgr, pts_creds->get_set(pts_creds));
	}

	/* attach file measurement database */
	uri = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.database", NULL);
	pts_db = pts_database_create(uri);

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

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_attestation_state_create(connection_id);
			return imv_attestation->create_state(imv_attestation, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imv_attestation->delete_state(imv_attestation, connection_id);
		case TNC_CONNECTION_STATE_HANDSHAKE:
		default:
			return imv_attestation->change_state(imv_attestation, connection_id,
												 new_state, NULL);
	}
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	linked_list_t *attr_list;
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;
	TNC_Result result;

	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imv_attestation_state_t*)state;
	attr_list = linked_list_create();

	if (imv_attestation_build(attr_list, attestation_state, supported_algorithms,
							  supported_dh_groups, pts_db))
	{
		if (attr_list->get_count(attr_list))
		{
			result = imv_attestation->send_message(imv_attestation,
							connection_id, FALSE, 0, TNC_IMCID_ANY,	attr_list);
		}
		else
		{
			result = TNC_RESULT_SUCCESS;
		}
		attr_list->destroy(attr_list);
	}
	else
	{
		attr_list->destroy_offset(attr_list, offsetof(pa_tnc_attr_t, destroy));
		result = TNC_RESULT_FATAL;
	}

	return result;
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
	pen_type_t type;
	linked_list_t *attr_list;
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;
	pts_t *pts;
	enumerator_t *enumerator;
	TNC_Result result;

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMV state */
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imv_attestation_state_t*)state;
	pts = attestation_state->get_pts(attestation_state);

	/* parse received PA-TNC message and automatically handle any errors */
	result = imv_attestation->receive_message(imv_attestation, state, msg,
					 msg_vid, msg_subtype, src_imc_id, dst_imv_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}

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

					DBG1(DBG_IMV, "received TCG-PTS error '%N'",
						 pts_error_code_names, error_code.type);
					DBG1(DBG_IMV, "error information: %B", &msg_info);

					result = TNC_RESULT_FATAL;
				}
			}
			else if (type.type == IETF_ATTR_PRODUCT_INFORMATION)
			{
				ietf_attr_product_info_t *attr_cast;
				char *platform_info;

				attr_cast = (ietf_attr_product_info_t*)attr;
				platform_info = attr_cast->get_info(attr_cast, NULL, NULL);
				pts->set_platform_info(pts, platform_info);
			}
		}
		else if (type.vendor_id == PEN_TCG)
		{
			if (!imv_attestation_process(attr, attr_list, attestation_state,
				supported_algorithms,supported_dh_groups, pts_db, pts_credmgr))
			{
				result = TNC_RESULT_FATAL;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (result != TNC_RESULT_SUCCESS)
	{
		attr_list->destroy_offset(attr_list, offsetof(pa_tnc_attr_t, destroy));
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		return imv_attestation->provide_recommendation(imv_attestation,
													   connection_id, src_imc_id);
	}

	if (attr_list->get_count(attr_list))
	{
		result = imv_attestation->send_message(imv_attestation, connection_id,
										FALSE, 0, TNC_IMCID_ANY, attr_list);
		attr_list->destroy(attr_list);
		return result;
	}
	attr_list->destroy(attr_list);

	/* check the IMV state for the next PA-TNC attributes to send */
	result = send_message(connection_id);
	if (result != TNC_RESULT_SUCCESS)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		return imv_attestation->provide_recommendation(imv_attestation,
													   connection_id, src_imc_id);
	}

	if (attestation_state->get_handshake_state(attestation_state) ==
		IMV_ATTESTATION_STATE_END)
	{
		if (attestation_state->get_file_meas_request_count(attestation_state))
		{
			DBG1(DBG_IMV, "failure due to %d pending file measurements",
				attestation_state->get_file_meas_request_count(attestation_state));
			attestation_state->set_measurement_error(attestation_state);
		}
		if (attestation_state->get_measurement_error(attestation_state))
		{
			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);
		}
		else
		{
			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_COMPLIANT);
		}
		return imv_attestation->provide_recommendation(imv_attestation,
													   connection_id, src_imc_id);
	}

	return result;
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
	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_attestation->provide_recommendation(imv_attestation,
												   connection_id, TNC_IMCID_ANY);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	/* get current IMV state */
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imv_attestation_state_t*)state;

	/* Check if IMV has to initiate the PA-TNC exchange */
	if (attestation_state->get_handshake_state(attestation_state) ==
		IMV_ATTESTATION_STATE_INIT)
	{
		return send_message(connection_id);
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.8.9 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Terminate(TNC_IMVID imv_id)
{
	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (pts_creds)
	{
		pts_credmgr->remove_set(pts_credmgr, pts_creds->get_set(pts_creds));
		pts_creds->destroy(pts_creds);
	}
	DESTROY_IF(pts_db);
	DESTROY_IF(pts_credmgr);

	libpts_deinit();

	imv_attestation->destroy(imv_attestation);
	imv_attestation = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_ProvideBindFunction(TNC_IMVID imv_id,
								TNC_TNCS_BindFunctionPointer bind_function)
{
	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_attestation->bind_functions(imv_attestation, bind_function);
}
