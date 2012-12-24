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
#include <imv/imv_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_string_version.h>

#include <libpts.h>

#include <pts/pts.h>
#include <pts/pts_database.h>
#include <pts/pts_creds.h>

#include <tcg/tcg_attr.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/debug.h>
#include <credentials/credential_manager.h>
#include <collections/linked_list.h>

/* IMV definitions */

static const char imv_name[] = "Attestation";

static pen_type_t msg_types[] = {
	{ PEN_TCG,  PA_SUBTYPE_TCG_PTS },
	{ PEN_IETF, PA_SUBTYPE_IETF_OPERATING_SYSTEM }
};

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
	imv_attestation = imv_agent_create(imv_name, msg_types, countof(msg_types),
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

static TNC_Result send_message(imv_state_t *state, imv_msg_t *out_msg)
{
	imv_attestation_state_t *attestation_state;
	TNC_Result result;

	attestation_state = (imv_attestation_state_t*)state;

	if (imv_attestation_build(out_msg, attestation_state, supported_algorithms,
							  supported_dh_groups, pts_db))
	{
		result = out_msg->send(out_msg, TRUE);
	}
	else
	{
		result = TNC_RESULT_FATAL;
	}

	return result;
}

static TNC_Result receive_message(imv_state_t *state, imv_msg_t *in_msg)
{
	imv_attestation_state_t *attestation_state;
	imv_msg_t *out_msg;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t type;
	TNC_Result result;
	pts_t *pts;
	chunk_t os_name = chunk_empty;
	chunk_t os_version = chunk_empty;
	bool fatal_error = FALSE;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	attestation_state = (imv_attestation_state_t*)state;
	pts = attestation_state->get_pts(attestation_state);

	out_msg = imv_msg_create_as_reply(in_msg);
	out_msg->set_msg_type(out_msg, msg_types[0]);

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF)
		{
			switch (type.type)
			{
				case IETF_ATTR_PA_TNC_ERROR:
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
					break;
				}
				case IETF_ATTR_PRODUCT_INFORMATION:
				{
					ietf_attr_product_info_t *attr_cast;

					attr_cast = (ietf_attr_product_info_t*)attr;
					os_name = attr_cast->get_info(attr_cast, NULL, NULL);
					break;
				}
				case IETF_ATTR_STRING_VERSION:
				{
					ietf_attr_string_version_t *attr_cast;

					attr_cast = (ietf_attr_string_version_t*)attr;
					os_version = attr_cast->get_version(attr_cast, NULL, NULL);
					break;
				}
				default:
					break;
			}
		}
		else if (type.vendor_id == PEN_TCG)
		{
			if (!imv_attestation_process(attr, out_msg, attestation_state, 
				supported_algorithms,supported_dh_groups, pts_db, pts_credmgr))
			{
				result = TNC_RESULT_FATAL;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (os_name.len && os_version.len)
	{
		pts->set_platform_info(pts, os_name, os_version);
	}

	if (fatal_error || result != TNC_RESULT_SUCCESS)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return imv_attestation->provide_recommendation(imv_attestation, state);
	}

	/* send PA-TNC message with excl flag set */
	result = out_msg->send(out_msg, TRUE);

	if (result != TNC_RESULT_SUCCESS)
	{
		out_msg->destroy(out_msg);
		return result;
	}

	/* check the IMV state for the next PA-TNC attributes to send */
	result = send_message(state, out_msg);

	if (result != TNC_RESULT_SUCCESS)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return imv_attestation->provide_recommendation(imv_attestation, state);
	}

	if (attestation_state->get_handshake_state(attestation_state) ==
		IMV_ATTESTATION_STATE_END)
	{
		if (attestation_state->get_file_meas_request_count(attestation_state))
		{
			DBG1(DBG_IMV, "failure due to %d pending file measurements",
				attestation_state->get_file_meas_request_count(attestation_state));
			attestation_state->set_measurement_error(attestation_state,
								IMV_ATTESTATION_ERROR_FILE_MEAS_PEND);
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
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return imv_attestation->provide_recommendation(imv_attestation, state);
	}
	out_msg->destroy(out_msg);

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
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_data(imv_attestation, state, connection_id, 
									  msg_type, chunk_create(msg, msg_len));
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

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(imv_attestation, state, connection_id,
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

	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return imv_attestation->provide_recommendation(imv_attestation, state);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	if (!imv_attestation)
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
