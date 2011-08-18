/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include <imv/imv_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <tcg/tcg_attr.h>

#include <tcg/tcg_pts_attr_req_proto_caps.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_get_tpm_version_info.h>
#include <tcg/tcg_pts_attr_get_aik.h>
#include <tcg/tcg_pts_attr_req_funct_comp_evid.h>
#include <tcg/tcg_pts_attr_gen_attest_evid.h>
#include <tcg/tcg_pts_attr_req_file_meas.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>
#include <utils/linked_list.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

/* IMV definitions */

static const char imv_name[] = "Attestation";

#define IMV_VENDOR_ID			PEN_TCG
#define IMV_SUBTYPE				PA_SUBTYPE_TCG_PTS

/**
 * UTF-8 encoding of the character used to delimiter the filename
 */
#define SOLIDUS_UTF				0x002F
#define REVERSE_SOLIDUS_UTF		0x005C

static imv_agent_t *imv_attestation;

/**
 * Supported PTS measurement algorithms
 */
static pts_meas_algorithms_t supported_algorithms = 0;

/**
 * List of files and directories to measure
 */
static linked_list_t *file_list, *directory_list;

/**
 * Monotonic increasing number for Request File Measurement attribute
 */
static u_int16_t request_id_counter = 0;

/**
 * Struct to hold file or directory name with the request ID for Request File Measurement attribute
 */
typedef struct measurement_req_entry_t measurement_req_entry_t;

struct measurement_req_entry_t {
	char *path;
	u_int16_t request_id;
};

/**
 * see section 3.7.1 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	char *hash_alg;

	if (imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imv_attestation = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
								imv_id, actual_version);
	if (!imv_attestation ||
		!tcg_pts_probe_meas_algorithms(&supported_algorithms))
	{
		return TNC_RESULT_FATAL;
	}
	if (min_version > TNC_IFIMV_VERSION_1 || max_version < TNC_IFIMV_VERSION_1)
	{
		DBG1(DBG_IMV, "no common IF-IMV version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}

	/* Specify supported PTS measurement algorithms */
	hash_alg = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.hash_algorithm", "sha256");
	if (!strcaseeq(hash_alg, "sha384") && !strcaseeq(hash_alg, "sha2_384"))
	{
		/* remove SHA384 algorithm */
		supported_algorithms &= ~PTS_MEAS_ALGO_SHA384;
	}
	if (strcaseeq(hash_alg, "sha1"))
	{
		/* remove SHA256 algorithm */
		supported_algorithms &= ~PTS_MEAS_ALGO_SHA256;
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
	imv_attestation_state_t *attestation_state;
	enumerator_t *enumerator;
	char *files;
	char *directories;
	measurement_req_entry_t *entry;
	char *token;

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
			if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
			{
				return TNC_RESULT_FATAL;
			}
			state->change_state(state, new_state);
			attestation_state = (imv_attestation_state_t*)state;
			
			/** Get the files to measure for
			 * PTS Request File Measurement attribute
			 */
			
			file_list = linked_list_create();
			directory_list = linked_list_create();
			
			files = lib->settings->get_str(lib->settings,
					"libimcv.plugins.imc-attestation.files", "none");
			enumerator = enumerator_create_token(files, " ", " ");
			while (enumerator->enumerate(enumerator, &token))
			{
				entry = malloc_thing(measurement_req_entry_t);
				token = strdup(token);
				entry->path = token;
				entry->request_id = request_id_counter;
				file_list->insert_last(file_list, entry);
				free(token);
				request_id_counter ++;
			}
			
			/** Get the directories to measure for
			 * PTS Request File Measurement attribute
			 */
			
			directories = lib->settings->get_str(lib->settings,
					"libimcv.plugins.imc-attestation.directories", "none");
			enumerator = enumerator_create_token(directories, " ", " ");
			while (enumerator->enumerate(enumerator, &token))
			{
				entry = malloc_thing(measurement_req_entry_t);
				token = strdup(token);
				entry->path = token;
				entry->request_id = request_id_counter;
				directory_list->insert_last(directory_list, entry);
				free(token);
				request_id_counter ++;
			}
			enumerator->destroy(enumerator);
			return TNC_RESULT_SUCCESS;
		default:
			return imv_attestation->change_state(imv_attestation, connection_id,
												 new_state, NULL);
	}
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *attr;
	TNC_Result result;
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;
	imv_attestation_handshake_state_t handshake_state;
	
	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	attestation_state = (imv_attestation_state_t*)state;
	handshake_state = attestation_state->get_handshake_state(attestation_state);
	
	/* Switch on the attribute type IMV has received */
	switch (handshake_state)
	{
		case IMV_ATTESTATION_STATE_INIT:
		{
			pts_proto_caps_flag_t flags;

			/* Send Request Protocol Capabilities attribute */
			flags = PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_VER |
					PTS_PROTO_CAPS_CURRENT;
			attr = tcg_pts_attr_req_proto_caps_create(flags);
			break;
		}
		case IMV_ATTESTATION_STATE_PROTO_CAP:
		{
			/* Send Measurement Algorithms attribute */
			attr = tcg_pts_attr_meas_algo_create(supported_algorithms, FALSE);
			break;
		}
		case IMV_ATTESTATION_STATE_MEAS_ALGO:
		{
			/* Send Get TPM Version Information attribute */
			attr = tcg_pts_attr_get_tpm_version_info_create();
			break;
		}
		case IMV_ATTESTATION_STATE_TPM_INFO:
		{
			/* Send Get AIK attribute */
			/* TODO: Uncomment when the retrieving of AIK on IMC side is implemented */
			//attr = tcg_pts_attr_get_aik_create();
			//break;
		}
		case IMV_ATTESTATION_STATE_AIK:
		{
			/* Send Request File Measurement attribute */
			enumerator_t *enumerator;
			measurement_req_entry_t *entry;
			char *path;
			u_int16_t request_id;
			u_int32_t delimiter = SOLIDUS_UTF;
			
			msg = pa_tnc_msg_create();
			
			/** 
			 * Add files to measure to PTS Request File Measurement attribute
			 */
			enumerator = enumerator_create_single(file_list, NULL);
			while (enumerator->enumerate(enumerator, &entry))
			{
				attr = tcg_pts_attr_req_file_meas_create(false, 
							entry->request_id, delimiter, 
							chunk_create(entry->path, strlen(entry->path)));
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
			}
			/** Add directories to measure to  PTS Request File Measurement attribute
			 */
			enumerator = enumerator_create_single(directory_list, NULL);
			while (enumerator->enumerate(enumerator, &entry))
			{
				attr = tcg_pts_attr_req_file_meas_create(true, 
							entry->request_id, delimiter, 
							chunk_create(entry->path, strlen(entry->path)));
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
			}
			enumerator->destroy(enumerator);
			goto end;
		}
		case IMV_ATTESTATION_STATE_SIMPLE_COMP_EVID:
		case IMV_ATTESTATION_STATE_SIMPLE_EVID_FINAL:
		case IMV_ATTESTATION_STATE_FILE_METADATA:
		case IMV_ATTESTATION_STATE_FILE_MEAS:
		case IMV_ATTESTATION_STATE_IML:
			DBG1(DBG_IMV, "Attestation IMV has nothing to send: \"%s\"", handshake_state);
			return TNC_RESULT_FATAL;
		default:
			DBG1(DBG_IMV, "Attestation IMV is in unknown state: \"%s\"", handshake_state);
			return TNC_RESULT_FATAL;
	}
	
	attr->set_noskip_flag(attr, TRUE);
	msg = pa_tnc_msg_create();
	msg->add_attribute(msg, attr);
	
end:
	msg->build(msg);
	result = imv_attestation->send_message(imv_attestation, connection_id,
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
	imv_attestation_state_t *imv_attestation_state;
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error = FALSE;

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

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imv_attestation->receive_message(imv_attestation, connection_id,
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
			u_int32_t offset;

			error_attr = (ietf_attr_pa_tnc_error_t*)attr;
			error_code = error_attr->get_error_code(error_attr);
			msg_info = error_attr->get_msg_info(error_attr);

			DBG1(DBG_IMV, "received PA-TNC error '%N' concerning message %#B",
				 pa_tnc_error_code_names, error_code, &msg_info);
			switch (error_code)
			{
				case PA_ERROR_INVALID_PARAMETER:
					offset = error_attr->get_offset(error_attr);
					DBG1(DBG_IMV, "  occurred at offset of %u bytes", offset);
					break;
				case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
					attr_info = error_attr->get_attr_info(error_attr);
					DBG1(DBG_IMV, "  unsupported attribute %#B", &attr_info);
					break;
				default:
					break;
			}
			fatal_error = TRUE;
		}
		else if (attr->get_vendor_id(attr) == PEN_TCG)
		{
			/**
			 * Handle TCG PTS attributes
			 */
			switch(attr->get_type(attr))
			{
				case TCG_PTS_PROTO_CAPS:
					break;
				case TCG_PTS_MEAS_ALGO_SELECTION:
					break;
				case TCG_PTS_TPM_VERSION_INFO:
					break;
				case TCG_PTS_AIK:
					break;
				
				/* PTS-based Attestation Evidence */
				case TCG_PTS_SIMPLE_COMP_EVID:
					break;
				case TCG_PTS_SIMPLE_EVID_FINAL:
					break;
				case TCG_PTS_FILE_MEAS:
					break;
				
				/* TODO: Not implemented yet */
				case TCG_PTS_DH_NONCE_PARAMS_RESP:
				case TCG_PTS_UNIX_FILE_META:
				case TCG_PTS_INTEG_MEAS_LOG:
				/* Attributes using XML */
				case TCG_PTS_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_VERIFICATION_RESULT:
				case TCG_PTS_INTEG_REPORT:
				/* On Windows only*/
				case TCG_PTS_WIN_FILE_META:
				case TCG_PTS_REGISTRY_VALUE:
				/* Received on IMC side only*/
				case TCG_PTS_REQ_PROTO_CAPS:
				case TCG_PTS_DH_NONCE_PARAMS_REQ:
				case TCG_PTS_DH_NONCE_FINISH:
				case TCG_PTS_MEAS_ALGO:
				case TCG_PTS_GET_TPM_VERSION_INFO:
				case TCG_PTS_REQ_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_UPDATE_TEMPL_REF_MANI:
				case TCG_PTS_GET_AIK:
				case TCG_PTS_REQ_FUNCT_COMP_EVID:
				case TCG_PTS_GEN_ATTEST_EVID:
				case TCG_PTS_REQ_FILE_META:
				case TCG_PTS_REQ_FILE_MEAS:
				case TCG_PTS_REQ_INTEG_MEAS_LOG:
				default:
					DBG1(DBG_IMV, "received unsupported attribute '%N'",
						tcg_attr_names, attr->get_type(attr));
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);			  
		return imv_attestation->provide_recommendation(imv_attestation, connection_id);
	}

	return imv_attestation->provide_recommendation(imv_attestation, connection_id);
}

/**
 * see section 3.7.4 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_SolicitRecommendation(TNC_IMVID imv_id,
										 TNC_ConnectionID connection_id)
{
	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_attestation->provide_recommendation(imv_attestation, connection_id);
}

/**
 * see section 3.7.5 of TCG TNC IF-IMV Specification 1.2
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
 * see section 3.7.6 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_Terminate(TNC_IMVID imv_id)
{
	if (!imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imv_attestation->destroy(imv_attestation);
	imv_attestation = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.2
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
