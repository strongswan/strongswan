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
#include <ietf/ietf_attr_product_info.h>

#include <libpts.h>

#include <pts/pts_database.h>
#include <pts/pts_creds.h>
#include <pts/pts_error.h>

#include <tcg/tcg_attr.h>
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
static pts_meas_algorithms_t supported_algorithms = 0;

/**
 * Supported PTS Diffie Hellman Groups
 */
static pts_dh_group_t supported_dh_groups = 0;

/**
 * High Entropy Random Data
 * used in calculation of shared secret for the assessment session
 */
static char *initiator_nonce = NULL;

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
 * TRUE if DH Nonce Parameters Request attribute is sent
 */
static bool dh_nonce_req_sent = FALSE;

/**
 * see section 3.7.1 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	char *hash_alg, *dh_group, *uri, *cadir;
	rng_t *rng;

	if (imv_attestation)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
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
	imv_attestation = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
									   imv_id, actual_version);
	if (!imv_attestation)
	{
		return TNC_RESULT_FATAL;
	}

	libpts_init();
	
	/* Create a initiator nonce */
	initiator_nonce = (char*)malloc(NONCE_LEN);
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (rng)
	{
		rng->get_bytes(rng, NONCE_LEN, initiator_nonce);
		rng->destroy(rng);
	}

	if (min_version > TNC_IFIMV_VERSION_1 || max_version < TNC_IFIMV_VERSION_1)
	{
		DBG1(DBG_IMV, "no common IF-IMV version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}

	/**
	 * Specify supported PTS measurement algorithms
	 *
	 * sha1 :  PTS_MEAS_ALGO_SHA1
	 * sha256: PTS_MEAS_ALGO_SHA1 | PTS_MEAS_ALGO_SHA256
	 * sha384: PTS_MEAS_ALGO_SHA1 | PTS_MEAS_ALGO_SHA256 | PTS_MEAS_ALGO_SHA384
	 *
	 * we expect the PTS-IMC to select the strongest supported algorithm
	 */
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

	/**
	 * Specify supported PTS Diffie Hellman Groups
	 *
	 * ike2: PTS_DH_GROUP_IKE2
	 * ike5: PTS_DH_GROUP_IKE2 | PTS_DH_GROUP_IKE5
	 * ike14: PTS_DH_GROUP_IKE2 | PTS_DH_GROUP_IKE5 | PTS_DH_GROUP_IKE14
	 * ike19: PTS_DH_GROUP_IKE2 | PTS_DH_GROUP_IKE5 | PTS_DH_GROUP_IKE14 | PTS_DH_GROUP_IKE19
	 * ike20: PTS_DH_GROUP_IKE2 | PTS_DH_GROUP_IKE5 | PTS_DH_GROUP_IKE14 | PTS_DH_GROUP_IKE19 | PTS_DH_GROUP_IKE20
	 *
	 * we expect the PTS-IMC to select the strongest supported group
	 */
	dh_group = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-attestation.dh_group", "ike19");
	if (!pts_update_supported_dh_groups(dh_group, &supported_dh_groups))
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
 * see section 3.7.2 of TCG TNC IF-IMV Specification 1.2
 */
TNC_Result TNC_IMV_NotifyConnectionChange(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;
	TNC_Result result;

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
			result = imv_attestation->change_state(imv_attestation, connection_id,
												   new_state, &state);
			if (result != TNC_RESULT_SUCCESS)
			{
				return result;
			}
			attestation_state = (imv_attestation_state_t*)state;

			/* TODO: Get some configurations */

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
	pts_t *pts;
	imv_state_t *state;
	imv_attestation_state_t *attestation_state;
	imv_attestation_handshake_state_t handshake_state;
	TNC_Result result;

	if (!imv_attestation->get_state(imv_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imv_attestation_state_t*)state;
	handshake_state = attestation_state->get_handshake_state(attestation_state);
	pts = attestation_state->get_pts(attestation_state);

	msg = pa_tnc_msg_create();

	/* Jump to Measurement state if IMC has no TPM */
	if (handshake_state == IMV_ATTESTATION_STATE_TPM_INIT &&
		!(pts->get_proto_caps(pts) & PTS_PROTO_CAPS_T))
	{
		handshake_state = IMV_ATTESTATION_STATE_MEAS;
		DBG3(DBG_IMV, "TPM is not available on IMC side, ",
			 "jumping to measurement phase");
	}

	/* Switch on the attribute type IMV has received */
	switch (handshake_state)
	{
		case IMV_ATTESTATION_STATE_INIT:
		{
			pts_proto_caps_flag_t flags;

			/* Send Request Protocol Capabilities attribute */
			flags = pts->get_proto_caps(pts);
			attr = tcg_pts_attr_proto_caps_create(flags, TRUE);
			attr->set_noskip_flag(attr, TRUE);
			msg->add_attribute(msg, attr);

			/* Send Measurement Algorithms attribute */
			attr = tcg_pts_attr_meas_algo_create(supported_algorithms, FALSE);
			attr->set_noskip_flag(attr, TRUE);
			msg->add_attribute(msg, attr);

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_TPM_INIT);
			break;
		}
		case IMV_ATTESTATION_STATE_TPM_INIT:
		{
			if (!dh_nonce_req_sent)
			{
				/* Send DH nonce parameters request attribute */
				attr = tcg_pts_attr_dh_nonce_params_req_create(0, supported_dh_groups);
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
				dh_nonce_req_sent = TRUE;
			}
			else
			{
				pts_meas_algorithms_t selected_algorithm;
				chunk_t initiator_pub_val;

				/* Send DH nonce finish attribute */
				selected_algorithm = pts->get_meas_algorithm(pts);
				initiator_pub_val = pts->get_my_pub_val(pts);
				attr = tcg_pts_attr_dh_nonce_finish_create(NONCE_LEN,
									selected_algorithm,
									chunk_create(initiator_nonce, NONCE_LEN),
									initiator_pub_val);
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);

				/* Send Get TPM Version attribute */
				attr = tcg_pts_attr_get_tpm_version_info_create();
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);

				/* Send Get AIK attribute */
				attr = tcg_pts_attr_get_aik_create();
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);

				attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_MEAS);
			}

			break;
		}
		case IMV_ATTESTATION_STATE_MEAS:
		{

			enumerator_t *enumerator;
			u_int32_t delimiter = SOLIDUS_UTF;
			char *platform_info, *pathname;
			u_int16_t request_id;
			int id, type;
			bool is_dir;

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_COMP_EVID);

			/* Get Platform and OS of the PTS-IMC */
			platform_info = pts->get_platform_info(pts);

			if (!pts_db || !platform_info)
			{
				DBG1(DBG_IMV, "%s%s%s not available",
					(pts_db) ? "" : "pts database",
					(!pts_db && !platform_info) ? "and" : "",
					(platform_info) ? "" : "platform info");
				break;
			}
			DBG1(DBG_IMV, "platform is '%s'", platform_info);

			/* Send Request File Metadata attribute */
			attr = tcg_pts_attr_req_file_meta_create(FALSE, SOLIDUS_UTF, "/etc/tnc_config");
			attr->set_noskip_flag(attr, TRUE);
			msg->add_attribute(msg, attr);

			/* Send Request File Measurement attribute */
			enumerator = pts_db->create_file_enumerator(pts_db, platform_info);
			if (!enumerator)
			{
				break;
			}
			while (enumerator->enumerate(enumerator, &id, &type, &pathname))
			{
				is_dir = (type != 0);
				request_id = attestation_state->add_request(attestation_state,
															id, is_dir);
				DBG2(DBG_IMV, "measurement request %d for %s '%s'",
					 request_id, is_dir ? "directory" : "file", pathname);
				attr = tcg_pts_attr_req_file_meas_create(is_dir, request_id,
													 delimiter, pathname);
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
			}
			enumerator->destroy(enumerator);
			break;
		}
		case IMV_ATTESTATION_STATE_COMP_EVID:
		{
			pts_attr_req_funct_comp_evid_flag_t flags;
			u_int32_t sub_comp_depth;
			pts_qualifier_t qualifier;
			pts_funct_comp_name_t name;

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_END);

			flags = PTS_REQ_FUNC_COMP_FLAG_PCR;
			sub_comp_depth = 1;
			qualifier.kernel = FALSE;
			qualifier.sub_component = FALSE;
			qualifier.type = PTS_FUNC_COMP_TYPE_ALL;
			name = PTS_FUNC_COMP_NAME_BIOS;

			/* Send Request Functional Component Evidence attribute */
			attr = tcg_pts_attr_req_funct_comp_evid_create(flags, sub_comp_depth,
														PEN_TCG, qualifier, name);
			attr->set_noskip_flag(attr, TRUE);
			msg->add_attribute(msg, attr);
			/* Send Generate Attestation Evidence attribute */
			attr = tcg_pts_attr_gen_attest_evid_create();
			attr->set_noskip_flag(attr, TRUE);
			msg->add_attribute(msg, attr);

			break;
		}
		default:
			DBG1(DBG_IMV, "Attestation IMV is in unknown state: \"%s\"",
				 handshake_state);
			return TNC_RESULT_FATAL;
	}

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
	imv_attestation_state_t *attestation_state;
	pts_t *pts;
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error = FALSE;
	bool measurement_error = FALSE;
	linked_list_t *attr_list;
	chunk_t attr_info;

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
	result = imv_attestation->receive_message(imv_attestation, connection_id,
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
		if (attr->get_vendor_id(attr) == PEN_IETF)
		{
			if (attr->get_type(attr) == IETF_ATTR_PA_TNC_ERROR)
			{
				ietf_attr_pa_tnc_error_t *error_attr;
				pen_t error_vendor_id;
				pa_tnc_error_code_t error_code;
				chunk_t msg_info, attr_info;
				u_int32_t offset;

				error_attr = (ietf_attr_pa_tnc_error_t*)attr;
				error_vendor_id = error_attr->get_vendor_id(error_attr);
				error_code = error_attr->get_error_code(error_attr);
				msg_info = error_attr->get_msg_info(error_attr);

				if (error_vendor_id == PEN_IETF)
				{
					DBG1(DBG_IMV, "received PA-TNC error '%N' "
								  "concerning message %#B",
						 pa_tnc_error_code_names, error_code, &msg_info);

					switch (error_code)
					{
						case PA_ERROR_INVALID_PARAMETER:
							offset = error_attr->get_offset(error_attr);
							DBG1(DBG_IMV, "  occurred at offset of %u bytes",
								 offset);
							break;
						case PA_ERROR_ATTR_TYPE_NOT_SUPPORTED:
							attr_info = error_attr->get_attr_info(error_attr);
							DBG1(DBG_IMV, "  unsupported attribute %#B",
								 &attr_info);
							break;
						default:
							break;
					}
				}
				else if (error_vendor_id == PEN_TCG)
				{
					DBG1(DBG_IMV, "received TCG-PTS error '%N'",
						 pts_error_code_names, error_code);
					DBG1(DBG_IMV, "error information: %B", &msg_info);
				}
				fatal_error = TRUE;
			}
			else if (attr->get_type(attr) == IETF_ATTR_PRODUCT_INFORMATION)
			{
				ietf_attr_product_info_t *attr_cast;
				char *platform_info;

				attr_cast = (ietf_attr_product_info_t*)attr;
				platform_info = attr_cast->get_info(attr_cast, NULL, NULL);
				pts->set_platform_info(pts, platform_info);
			}
		}
		else if (attr->get_vendor_id(attr) == PEN_TCG)
		{
			switch (attr->get_type(attr))
			{
				case TCG_PTS_PROTO_CAPS:
				{
					tcg_pts_attr_proto_caps_t *attr_cast;
					pts_proto_caps_flag_t flags;

					attr_cast = (tcg_pts_attr_proto_caps_t*)attr;
					flags = attr_cast->get_flags(attr_cast);
					pts->set_proto_caps(pts, flags);
					break;
				}
				case TCG_PTS_MEAS_ALGO_SELECTION:
				{
					tcg_pts_attr_meas_algo_t *attr_cast;
					pts_meas_algorithms_t selected_algorithm;

					attr_cast = (tcg_pts_attr_meas_algo_t*)attr;
					selected_algorithm = attr_cast->get_algorithms(attr_cast);
					pts->set_meas_algorithm(pts, selected_algorithm);
					break;
				}
				case TCG_PTS_DH_NONCE_PARAMS_RESP:
				{
					tcg_pts_attr_dh_nonce_params_resp_t *attr_cast;
					u_int8_t nonce_len;
					pts_dh_group_t dh_group;
					pts_meas_algorithms_t offered_algorithms, selected_algorithm;
					chunk_t responder_nonce, initiator_non, responder_pub_val;

					attr_cast = (tcg_pts_attr_dh_nonce_params_resp_t*)attr;

					nonce_len = attr_cast->get_nonce_len(attr_cast);
					if (nonce_len < 0 || nonce_len <= 16)
					{
						attr_info = attr->get_value(attr);
						attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
									TCG_PTS_BAD_NONCE_LENGTH, attr_info);
						attr_list->insert_last(attr_list, attr);
						break;
					}

					dh_group = attr_cast->get_dh_group(attr_cast);

					offered_algorithms = attr_cast->get_hash_algo_set(attr_cast);
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

					selected_algorithm = pts->get_meas_algorithm(pts);
					responder_nonce = attr_cast->get_responder_nonce(attr_cast);
					responder_pub_val = attr_cast->get_responder_pub_val(attr_cast);
					initiator_non = chunk_create(initiator_nonce, NONCE_LEN);
					
					/* Calculate secret assessment value */
					if (!pts->create_dh(pts, dh_group))
					{
						return TNC_RESULT_FATAL;
					}
					pts->set_other_pub_val(pts, responder_pub_val);

					DBG3(DBG_IMV, "Initiator nonce: %B", &initiator_non);
					DBG3(DBG_IMV, "Responder nonce: %B", &responder_nonce);
					if (!pts->calculate_secret(pts, initiator_non,
							responder_nonce, selected_algorithm))
					{
						return TNC_RESULT_FATAL;
					}
					break;
				}
				case TCG_PTS_TPM_VERSION_INFO:
				{
					tcg_pts_attr_tpm_version_info_t *attr_cast;
					chunk_t tpm_version_info;

					attr_cast = (tcg_pts_attr_tpm_version_info_t*)attr;
					tpm_version_info = attr_cast->get_tpm_version_info(attr_cast);
					pts->set_tpm_version_info(pts, tpm_version_info);
					break;
				}
				case TCG_PTS_AIK:
				{
					tcg_pts_attr_aik_t *attr_cast;
					certificate_t *aik, *issuer;
					enumerator_t *e;
					bool trusted = FALSE;

					attr_cast = (tcg_pts_attr_aik_t*)attr;
					aik = attr_cast->get_aik(attr_cast);
					if (!aik)
					{
						/* TODO generate error attribute */
						break;
					}
					if (aik->get_type(aik) == CERT_X509)
					{
						DBG1(DBG_IMV, "verifying AIK certificate");
						e = pts_credmgr->create_trusted_enumerator(pts_credmgr,
									KEY_ANY, aik->get_issuer(aik), FALSE);
						while (e->enumerate(e, &issuer))
						{
							if (aik->issued_by(aik, issuer))
							{
								trusted = TRUE;
								break;
							}
						}
						e->destroy(e);
						DBG1(DBG_IMV, "AIK certificate is %strusted",
									   trusted ? "" : "not ");
					}
					pts->set_aik(pts, aik);
					break;
				}

				/* PTS-based Attestation Evidence */
				case TCG_PTS_SIMPLE_COMP_EVID:
				{
					/** TODO: Implement saving the PCR number, Hash Algo = communicated one,
					 * PCR transform (truncate SHA256, SHA384), PCR before and after values
					 */
					break;
				}

				case TCG_PTS_SIMPLE_EVID_FINAL:
				{
					/** TODO: Implement construct Quote structure over saved values from
					 * TCG_PTS_SIMPLE_COMP_EVID and compare with received one
					 */
					break;
				}

				case TCG_PTS_FILE_MEAS:
				{
					tcg_pts_attr_file_meas_t *attr_cast;
					u_int16_t request_id;
					int file_count, file_id;
					pts_meas_algorithms_t algo;
					pts_file_meas_t *measurements;
					char *platform_info;
					enumerator_t *e_hash;
					bool is_dir;

					platform_info = pts->get_platform_info(pts);
					if (!pts_db || !platform_info)
					{
						break;
					}

					attr_cast = (tcg_pts_attr_file_meas_t*)attr;
					measurements = attr_cast->get_measurements(attr_cast);
					algo = pts->get_meas_algorithm(pts);
					request_id = measurements->get_request_id(measurements);
					file_count = measurements->get_file_count(measurements);

					DBG1(DBG_IMV, "measurement request %d returned %d file%s:",
						 request_id, file_count, (file_count == 1) ? "":"s");

					if (!attestation_state->check_off_request(attestation_state,
						request_id, &file_id, &is_dir))
					{
						DBG1(DBG_IMV, "  no entry found for this request");
						break;
					}

					/* check hashes from database against measurements */
					e_hash = pts_db->create_hash_enumerator(pts_db,
									platform_info, algo, file_id, is_dir);
					if (!measurements->verify(measurements, e_hash, is_dir))
					{
						measurement_error = TRUE;
					}
					e_hash->destroy(e_hash);
					break;
				}
				case TCG_PTS_UNIX_FILE_META:
				{
					tcg_pts_attr_file_meta_t *attr_cast;
					int file_count;
					pts_file_meta_t *metadata;
					enumerator_t *e;
					pts_file_metadata_t *entry;

					attr_cast = (tcg_pts_attr_file_meta_t*)attr;
					metadata = attr_cast->get_metadata(attr_cast);
					file_count = metadata->get_file_count(metadata);

					DBG1(DBG_IMV, "metadata request returned %d file%s:",
						 file_count, (file_count == 1) ? "":"s");

					e = metadata->create_enumerator(metadata);
					while(e->enumerate(e, &entry))
					{
						DBG1(DBG_IMV, "File name:          %s", entry->filename);
						DBG1(DBG_IMV, "     type:          %d", entry->type);
						DBG1(DBG_IMV, "     size:          %d", entry->filesize);
						DBG1(DBG_IMV, "     create time:   %s", ctime(&entry->create_time));
						DBG1(DBG_IMV, "     last modified: %s", ctime(&entry->last_modify_time));
						DBG1(DBG_IMV, "     last accessed: %s", ctime(&entry->last_access_time));
						DBG1(DBG_IMV, "     owner id:      %d", entry->owner_id);
						DBG1(DBG_IMV, "     group id:      %d", entry->group_id);
					}

					e->destroy(e);

					break;
				}

				/* TODO: Not implemented yet */
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
		return imv_attestation->provide_recommendation(imv_attestation,
													   connection_id);
	}

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
		result = imv_attestation->send_message(imv_attestation, connection_id,
							pa_tnc_msg->get_encoding(pa_tnc_msg));
		
		pa_tnc_msg->destroy(pa_tnc_msg);
		attr_list->destroy(attr_list);
		
		return result;
	}
	DESTROY_IF(attr_list);

	if (attestation_state->get_handshake_state(attestation_state) &
		IMV_ATTESTATION_STATE_END)
	{
		if (attestation_state->get_request_count(attestation_state))
		{
			DBG1(DBG_IMV, "failure due to %d pending file measurements",
				 attestation_state->get_request_count(attestation_state));
			measurement_error = TRUE;
		}
		if (measurement_error)
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
													   connection_id);
	}

	return send_message(connection_id);
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
 * see section 3.7.6 of TCG TNC IF-IMV Specification 1.2
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
	free(initiator_nonce);

	libpts_deinit();

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