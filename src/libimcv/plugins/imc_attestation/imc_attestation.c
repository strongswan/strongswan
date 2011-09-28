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

#include "imc_attestation_state.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>

#include <libpts.h>

#include <pts/pts_error.h>

#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_req.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_resp.h>
#include <tcg/tcg_pts_attr_dh_nonce_finish.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_get_tpm_version_info.h>
#include <tcg/tcg_pts_attr_tpm_version_info.h>
#include <tcg/tcg_pts_attr_get_aik.h>
#include <tcg/tcg_pts_attr_aik.h>
#include <tcg/tcg_pts_attr_req_funct_comp_evid.h>
#include <tcg/tcg_pts_attr_gen_attest_evid.h>
#include <tcg/tcg_pts_attr_simple_comp_evid.h>
#include <tcg/tcg_pts_attr_simple_evid_final.h>
#include <tcg/tcg_pts_attr_req_file_meas.h>
#include <tcg/tcg_pts_attr_file_meas.h>
#include <tcg/tcg_pts_attr_req_file_meta.h>
#include <tcg/tcg_pts_attr_unix_file_meta.h>

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
static pts_meas_algorithms_t supported_algorithms = 0;
 
/**
 * Supported PTS Diffie Hellman Groups
 */
static pts_dh_group_t supported_dh_groups = 0;

/**
 * High Entropy Random Data
 * used in calculation of shared secret for the assessment session
 */
static char *responder_nonce = NULL;

/**
 * see section 3.7.1 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_Initialize(TNC_IMCID imc_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	rng_t *rng;
	
	if (imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has already been initialized", imc_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	if (!pts_meas_probe_algorithms(&supported_algorithms))
	{
		return TNC_RESULT_FATAL;
	}
	if (!pts_probe_dh_groups(&supported_dh_groups))
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

	/* create a responder nonce */
	responder_nonce = (char*)malloc(NONCE_LEN);
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (rng)
	{
		rng->get_bytes(rng, NONCE_LEN, responder_nonce);
		rng->destroy(rng);
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
	/* TODO: Not used so far */
	//imc_attestation_state_t *attestation_state;

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
		case TNC_CONNECTION_STATE_DELETE:
			return imc_attestation->delete_state(imc_attestation, connection_id);
		case TNC_CONNECTION_STATE_HANDSHAKE:
		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
		default:
			return imc_attestation->change_state(imc_attestation, connection_id,
												  new_state, NULL);
	}
}


/**
 * see section 3.7.3 of TCG TNC IF-IMC Specification 1.2
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
		pa_tnc_msg_t *pa_tnc_msg;
		pa_tnc_attr_t *attr;

		pa_tnc_msg = pa_tnc_msg_create();
		attr = ietf_attr_product_info_create(0, 0, platform_info);
		pa_tnc_msg->add_attribute(pa_tnc_msg, attr);
		pa_tnc_msg->build(pa_tnc_msg);
		result = imc_attestation->send_message(imc_attestation, connection_id,
									pa_tnc_msg->get_encoding(pa_tnc_msg));
		pa_tnc_msg->destroy(pa_tnc_msg);
	}

	return result;
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
	linked_list_t *attr_list;
	imc_state_t *state;
	imc_attestation_state_t *attestation_state;
	enumerator_t *enumerator;
	pts_t *pts;
	TNC_Result result;
	bool fatal_error = FALSE;
	chunk_t attr_info;
	pts_error_code_t pts_error;
	bool valid_path;

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

	/* parse received PA-TNC message and automatically handle any errors */
	result = imc_attestation->receive_message(imc_attestation, connection_id,
									   chunk_create(msg, msg_len), msg_type,
									   &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}
	
	attr_list = linked_list_create();

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

			DBG1(DBG_IMC, "received PA-TNC error '%N' concerning message %#B",
				 pa_tnc_error_code_names, error_code, &msg_info);
			switch (error_code)
			{
				case PA_ERROR_INVALID_PARAMETER:
					offset = error_attr->get_offset(error_attr);
					DBG1(DBG_IMC, "  occurred at offset of %u bytes", offset);
					break;
				case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
					attr_info = error_attr->get_attr_info(error_attr);
					DBG1(DBG_IMC, "  unsupported attribute %#B", &attr_info);
					break;
				default:
					break;
			}
			fatal_error = TRUE;
		}
		else if (attr->get_vendor_id(attr) == PEN_TCG)
		{
			switch (attr->get_type(attr))
			{
				case TCG_PTS_REQ_PROTO_CAPS:
				{
					tcg_pts_attr_proto_caps_t *attr_cast;
					pts_proto_caps_flag_t imc_caps, imv_caps;

					attr_cast = (tcg_pts_attr_proto_caps_t*)attr;
					imv_caps = attr_cast->get_flags(attr_cast);
					imc_caps = pts->get_proto_caps(pts);
					pts->set_proto_caps(pts, imc_caps & imv_caps);

					/* Send PTS Protocol Capabilities attribute */
					attr = tcg_pts_attr_proto_caps_create(imc_caps & imv_caps,
														  FALSE);
					attr_list->insert_last(attr_list, attr);
					break;
				}
				case TCG_PTS_DH_NONCE_PARAMS_REQ:
				{
					tcg_pts_attr_dh_nonce_params_req_t *attr_cast;
					u_int8_t min_nonce_len;
					pts_dh_group_t offered_dh_groups, selected_dh_group;
					chunk_t responder_pub_val;

					attr_cast = (tcg_pts_attr_dh_nonce_params_req_t*)attr;
					min_nonce_len = attr_cast->get_min_nonce_len(attr_cast);
					if (NONCE_LEN < min_nonce_len || NONCE_LEN <= 16)
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
									TCG_PTS_BAD_NONCE_LENGTH, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					offered_dh_groups = attr_cast->get_dh_groups(attr_cast);

					if ((supported_dh_groups & PTS_DH_GROUP_IKE20) &&
						(offered_dh_groups & PTS_DH_GROUP_IKE20))
					{
						pts->set_dh_group(pts, PTS_DH_GROUP_IKE20);
					}
					else if ((supported_dh_groups & PTS_DH_GROUP_IKE19) &&
							 (offered_dh_groups & PTS_DH_GROUP_IKE19))
					{
						pts->set_dh_group(pts, PTS_DH_GROUP_IKE19);
					}
					else if ((supported_dh_groups & PTS_DH_GROUP_IKE14) &&
							 (offered_dh_groups & PTS_DH_GROUP_IKE14))
					{
						pts->set_dh_group(pts, PTS_DH_GROUP_IKE14);
					}
					else if ((supported_dh_groups & PTS_DH_GROUP_IKE5) &&
							 (offered_dh_groups & PTS_DH_GROUP_IKE5))
					{
						pts->set_dh_group(pts, PTS_DH_GROUP_IKE5);
					}
					else if ((supported_dh_groups & PTS_DH_GROUP_IKE2) &&
							 (offered_dh_groups & PTS_DH_GROUP_IKE2))
					{
						pts->set_dh_group(pts, PTS_DH_GROUP_IKE2);
					}
					else
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
									TCG_PTS_DH_GRPS_NOT_SUPPORTED, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					/* Send DH Nonce Parameters Response attribute */
					selected_dh_group = pts->get_dh_group(pts);
					if (!pts->create_dh(pts, selected_dh_group))
					{
						return TNC_RESULT_FATAL;
					}
					responder_pub_val = pts->get_my_pub_val(pts);

					attr = tcg_pts_attr_dh_nonce_params_resp_create(NONCE_LEN,
								selected_dh_group, supported_algorithms,
								chunk_create(responder_nonce, NONCE_LEN),
								responder_pub_val);
					attr_list->insert_last(attr_list, attr);
					break;
				}
				case TCG_PTS_DH_NONCE_FINISH:
				{
					tcg_pts_attr_dh_nonce_finish_t *attr_cast;
					u_int8_t nonce_len;
					pts_meas_algorithms_t selected_algorithm;
   					chunk_t initiator_nonce, initiator_pub_val, responder_non;

					attr_cast = (tcg_pts_attr_dh_nonce_finish_t*)attr;
					nonce_len = attr_cast->get_nonce_len(attr_cast);
					if (nonce_len < 0 || nonce_len <= 16)
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
									TCG_PTS_BAD_NONCE_LENGTH, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					selected_algorithm = attr_cast->get_hash_algo(attr_cast);
					initiator_pub_val = attr_cast->get_initiator_pub_val(attr_cast);
					initiator_nonce = attr_cast->get_initiator_nonce(attr_cast);
					responder_non = chunk_create(responder_nonce, NONCE_LEN);
					
					DBG3(DBG_IMC, "Initiator nonce: %B", &initiator_nonce);
					DBG3(DBG_IMC, "Responder nonce: %B", &responder_non);
					
					pts->set_other_pub_val(pts, initiator_pub_val);
					if (!pts->calculate_secret(pts, initiator_nonce,
										responder_non, selected_algorithm))
					{
						return TNC_RESULT_FATAL;
					}

					break;
				}
				case TCG_PTS_MEAS_ALGO:
				{
					tcg_pts_attr_meas_algo_t *attr_cast;
					pts_meas_algorithms_t offered_algorithms, selected_algorithm;

					attr_cast = (tcg_pts_attr_meas_algo_t*)attr;
					offered_algorithms = attr_cast->get_algorithms(attr_cast);

					if ((supported_algorithms & PTS_MEAS_ALGO_SHA384) &&
						(offered_algorithms & PTS_MEAS_ALGO_SHA384))
					{
						pts->set_meas_algorithm(pts, PTS_MEAS_ALGO_SHA384);
					}
					else if ((supported_algorithms & PTS_MEAS_ALGO_SHA256) &&
							 (offered_algorithms & PTS_MEAS_ALGO_SHA256))
					{
						pts->set_meas_algorithm(pts, PTS_MEAS_ALGO_SHA256);
					}

					else if ((supported_algorithms & PTS_MEAS_ALGO_SHA1) &&
							 (offered_algorithms & PTS_MEAS_ALGO_SHA1))
					{
						pts->set_meas_algorithm(pts, PTS_MEAS_ALGO_SHA1);
					}
					else
					{
						attr = pts_hash_alg_error_create(supported_algorithms);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					/* Send Measurement Algorithm Selection attribute */
					selected_algorithm = pts->get_meas_algorithm(pts);
					attr = tcg_pts_attr_meas_algo_create(selected_algorithm,
														 TRUE);
					attr_list->insert_last(attr_list, attr);
					break;
				}
	
				case TCG_PTS_GET_TPM_VERSION_INFO:
				{
					chunk_t tpm_version_info, attr_info;

					if (!pts->get_tpm_version_info(pts, &tpm_version_info))
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
									TCG_PTS_TPM_VERS_NOT_SUPPORTED, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
	
					/* Send TPM Version Info attribute */
					attr = tcg_pts_attr_tpm_version_info_create(tpm_version_info);
					attr_list->insert_last(attr_list, attr);
					break;
				}
	
				case TCG_PTS_GET_AIK:
				{
					certificate_t *aik;

					aik = pts->get_aik(pts);
					if (!aik)
					{
						DBG1(DBG_IMC, "no AIK certificate or public key available");
						break;
					}
	
					/* Send AIK attribute */
					attr = tcg_pts_attr_aik_create(aik);
					attr_list->insert_last(attr_list, attr);
					break;
				}
	
				/* PTS-based Attestation Evidence */
				case TCG_PTS_REQ_FUNCT_COMP_EVID:
				{
					tcg_pts_attr_req_funct_comp_evid_t *attr_cast;
					pts_proto_caps_flag_t negotiated_caps;
					pts_attr_req_funct_comp_evid_flag_t flags;
					u_int32_t sub_comp_depth;
					u_int32_t comp_name_vendor_id;
					u_int8_t family;
					pts_qualifier_t qualifier;
					pts_funct_comp_name_t name;

					attr_info = attr->get_value(attr);
					attr_cast = (tcg_pts_attr_req_funct_comp_evid_t*)attr;
					negotiated_caps = pts->get_proto_caps(pts);
					flags = attr_cast->get_flags(attr_cast);

					if (flags & PTS_REQ_FUNC_COMP_FLAG_TTC)
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_UNABLE_DET_TTC, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					if (flags & PTS_REQ_FUNC_COMP_FLAG_VER &&
						!(negotiated_caps & PTS_PROTO_CAPS_V))
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_UNABLE_LOCAL_VAL, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					if (flags & PTS_REQ_FUNC_COMP_FLAG_CURR &&
						!(negotiated_caps & PTS_PROTO_CAPS_C))
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_UNABLE_CUR_EVID, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					if (flags & PTS_REQ_FUNC_COMP_FLAG_PCR &&
						!(negotiated_caps & PTS_PROTO_CAPS_T))
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_UNABLE_DET_PCR, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					sub_comp_depth = attr_cast->get_sub_component_depth(attr_cast);
					/* TODO: Implement checking of components with its sub-components */
					if (sub_comp_depth != 1)
					{
						DBG1(DBG_IMC, "Current version of Attestation IMC does not support"
									  "sub component measurement deeper than 1. "
									   "Measuring top level component only.");
					}

					comp_name_vendor_id = attr_cast->get_comp_funct_name_vendor_id(attr_cast);
					if (comp_name_vendor_id != PEN_TCG)
					{
						DBG1(DBG_IMC, "Current version of Attestation IMC supports"
									  "only functional component namings by TCG ");
						break;
					}

					family = attr_cast->get_family(attr_cast);
					if (family)
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_INVALID_NAME_FAM, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					qualifier = attr_cast->get_qualifier(attr_cast);
					/* Check if Unknown or Wildcard was set for qualifier */
					if (qualifier.kernel && qualifier.sub_component &&
									(qualifier.type & PTS_FUNC_COMP_TYPE_ALL))
					{
						DBG2(DBG_IMC, "Wildcard was set for the qualifier of functional"
							" component. Identifying the component with name binary enumeration");
					}
					else if (!qualifier.kernel && !qualifier.sub_component &&
									(qualifier.type & PTS_FUNC_COMP_TYPE_UNKNOWN))
					{
						DBG2(DBG_IMC, "Unknown was set for the qualifier of functional"
							" component. Identifying the component with name binary enumeration");
					}
					else
					{
						/* TODO: Implement what todo with received qualifier */
					}

					name = attr_cast->get_comp_funct_name(attr_cast);
					switch (name)
					{
						case PTS_FUNC_COMP_NAME_BIOS:
						{
							/* TODO: Implement BIOS measurement */
							DBG1(DBG_IMC, "TODO: Implement BIOS measurement");
							break;
						}
						case PTS_FUNC_COMP_NAME_IGNORE:
						case PTS_FUNC_COMP_NAME_CRTM:
						case PTS_FUNC_COMP_NAME_PLATFORM_EXT:
						case PTS_FUNC_COMP_NAME_BOARD:
						case PTS_FUNC_COMP_NAME_INIT_LOADER:
						case PTS_FUNC_COMP_NAME_OPT_ROMS:
						default:
						{
							DBG1(DBG_IMC, "Unsupported Functional Component Name");
							break;
						}
					}

					break;
				}
				case TCG_PTS_GEN_ATTEST_EVID:
				{
					pts_simple_evid_final_flag_t flags;
					/* TODO: TPM quote operation over included PCR's */

					/* Send Simple Evidence Final attribute */
					flags = PTS_SIMPLE_EVID_FINAL_FLAG_NO;
					attr = tcg_pts_attr_simple_evid_final_create(flags, 0,
											chunk_empty, chunk_empty, chunk_empty);
					attr_list->insert_last(attr_list, attr);
					break;
				}
				case TCG_PTS_REQ_FILE_META:
				{
					tcg_pts_attr_req_file_meta_t *attr_cast;
					char *pathname;
					bool is_directory;
					u_int8_t delimiter;
					pts_file_meta_t *metadata;

					attr_info = attr->get_value(attr);
					attr_cast = (tcg_pts_attr_req_file_meta_t*)attr;
					is_directory = attr_cast->get_directory_flag(attr_cast);
					delimiter = attr_cast->get_delimiter(attr_cast);
					pathname = attr_cast->get_pathname(attr_cast);

					valid_path = pts->is_path_valid(pts, pathname, &pts_error);
					if (valid_path && pts_error)
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
												pts_error, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					else if (!valid_path)
					{
						break;
					}
					if (delimiter != SOLIDUS_UTF && delimiter != REVERSE_SOLIDUS_UTF)
					{
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
												TCG_PTS_INVALID_DELIMITER, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					/* Get File Metadata and send them to PTS-IMV */
					DBG2(DBG_IMC, "metadata request for %s '%s'",
							is_directory ? "directory" : "file",
							pathname);
					metadata = pts->get_metadata(pts, pathname, is_directory);

					if (!metadata)
					{
						/* TODO handle error codes from measurements */
						return TNC_RESULT_FATAL;
					}
					attr = tcg_pts_attr_unix_file_meta_create(metadata);
					attr->set_noskip_flag(attr, TRUE);
					attr_list->insert_last(attr_list, attr);

					break;
				}
				case TCG_PTS_REQ_FILE_MEAS:
				{
					tcg_pts_attr_req_file_meas_t *attr_cast;
					char *pathname;
					u_int16_t request_id;
					bool is_directory;
					u_int32_t delimiter;
					pts_file_meas_t *measurements;

					attr_info = attr->get_value(attr);
					attr_cast = (tcg_pts_attr_req_file_meas_t*)attr;
					is_directory = attr_cast->get_directory_flag(attr_cast);
					request_id = attr_cast->get_request_id(attr_cast);
					delimiter = attr_cast->get_delimiter(attr_cast);
					pathname = attr_cast->get_pathname(attr_cast);
					valid_path = pts->is_path_valid(pts, pathname, &pts_error);

					if (valid_path && pts_error)
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
												pts_error, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}
					else if (!valid_path)
					{
						break;
					}
					
					if (delimiter != SOLIDUS_UTF && delimiter != REVERSE_SOLIDUS_UTF)
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
												TCG_PTS_INVALID_DELIMITER, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					/* Do PTS File Measurements and send them to PTS-IMV */
					DBG2(DBG_IMC, "measurement request %d for %s '%s'",
						 request_id, is_directory ? "directory" : "file",
						 pathname);
					measurements = pts->do_measurements(pts, request_id,
											pathname, is_directory);
					if (!measurements)
					{
						/* TODO handle error codes from measurements */
						return TNC_RESULT_FATAL;
					}
					attr = tcg_pts_attr_file_meas_create(measurements);
					attr->set_noskip_flag(attr, TRUE);
					attr_list->insert_last(attr_list, attr);
					break;
				}
				/* TODO: Not implemented yet */
				case TCG_PTS_REQ_INTEG_MEAS_LOG:
				/* Attributes using XML */
				case TCG_PTS_REQ_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_UPDATE_TEMPL_REF_MANI:
				/* On Windows only*/
				case TCG_PTS_REQ_REGISTRY_VALUE:
				/* Received on IMV side only*/
				case TCG_PTS_PROTO_CAPS:
				case TCG_PTS_DH_NONCE_PARAMS_RESP:
				case TCG_PTS_MEAS_ALGO_SELECTION:
				case TCG_PTS_TPM_VERSION_INFO:
				case TCG_PTS_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_AIK:
				case TCG_PTS_SIMPLE_COMP_EVID:
				case TCG_PTS_SIMPLE_EVID_FINAL:
				case TCG_PTS_VERIFICATION_RESULT:
				case TCG_PTS_INTEG_REPORT:
				case TCG_PTS_UNIX_FILE_META:
				case TCG_PTS_FILE_MEAS:
				case TCG_PTS_INTEG_MEAS_LOG:
				default:
					DBG1(DBG_IMC, "received unsupported attribute '%N'",
						tcg_attr_names, attr->get_type(attr));
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	result = TNC_RESULT_SUCCESS;
	
	if (attr_list->get_count(attr_list))
	{
		pa_tnc_msg = pa_tnc_msg_create();

		enumerator = attr_list->create_enumerator(attr_list);
		while (enumerator->enumerate(enumerator, &attr))
		{
			pa_tnc_msg->add_attribute(pa_tnc_msg, attr);
		}
		enumerator->destroy(enumerator);

		pa_tnc_msg->build(pa_tnc_msg);
		result = imc_attestation->send_message(imc_attestation, connection_id,
							pa_tnc_msg->get_encoding(pa_tnc_msg));
		pa_tnc_msg->destroy(pa_tnc_msg);
	}
	attr_list->destroy(attr_list);

	return result;
}

/**
 * see section 3.7.5 of TCG TNC IF-IMC Specification 1.2
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
 * see section 3.7.6 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_Terminate(TNC_IMCID imc_id)
{
	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	free(responder_nonce);
	libpts_deinit();

	imc_attestation->destroy(imc_attestation);
	imc_attestation = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.2
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
