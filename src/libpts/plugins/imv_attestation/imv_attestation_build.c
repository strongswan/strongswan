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

#include "imv_attestation_build.h"
#include "imv_attestation_state.h"

#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_req.h>
#include <tcg/tcg_pts_attr_dh_nonce_finish.h>
#include <tcg/tcg_pts_attr_get_tpm_version_info.h>
#include <tcg/tcg_pts_attr_get_aik.h>
#include <tcg/tcg_pts_attr_req_func_comp_evid.h>
#include <tcg/tcg_pts_attr_gen_attest_evid.h>
#include <tcg/tcg_pts_attr_req_file_meas.h>
#include <tcg/tcg_pts_attr_req_file_meta.h>

#include <utils/debug.h>

bool imv_attestation_build(imv_msg_t *out_msg,
						   imv_attestation_state_t *attestation_state,
						   pts_meas_algorithms_t supported_algorithms,
						   pts_dh_group_t supported_dh_groups,
						   pts_database_t *pts_db)
{
	imv_attestation_handshake_state_t handshake_state;
	pts_t *pts;
	pa_tnc_attr_t *attr = NULL;

	handshake_state = attestation_state->get_handshake_state(attestation_state);
	pts = attestation_state->get_pts(attestation_state);

	/**
	 * Skip DH Nonce Parameters Request attribute when
	 *   DH Nonce Exchange is not selected by PTS-IMC side
	 */
	if (handshake_state == IMV_ATTESTATION_STATE_NONCE_REQ &&
		!(pts->get_proto_caps(pts) & PTS_PROTO_CAPS_D))
	{
		DBG2(DBG_IMV, "PTS-IMC does not support DH Nonce negotiation - "
					  "advancing to TPM Initialization");
		handshake_state = IMV_ATTESTATION_STATE_TPM_INIT;
	}

	/**
	 * Skip TPM Version Info and AIK attributes when
	 *   no TPM is available on the PTS-IMC side
	 */
	if (handshake_state == IMV_ATTESTATION_STATE_TPM_INIT &&
		!(pts->get_proto_caps(pts) & PTS_PROTO_CAPS_T))
	{
		DBG2(DBG_IMV, "PTS-IMC made no TPM available - "
					  "advancing to File Measurements");
		handshake_state = IMV_ATTESTATION_STATE_MEAS;
	}

	switch (handshake_state)
	{
		case IMV_ATTESTATION_STATE_INIT:
		{
			pts_proto_caps_flag_t flags;

			/* Send Request Protocol Capabilities attribute */
			flags = pts->get_proto_caps(pts);
			attr = tcg_pts_attr_proto_caps_create(flags, TRUE);
			attr->set_noskip_flag(attr, TRUE);
			out_msg->add_attribute(out_msg, attr);

			/* Send Measurement Algorithms attribute */
			attr = tcg_pts_attr_meas_algo_create(supported_algorithms, FALSE);
			attr->set_noskip_flag(attr, TRUE);
			out_msg->add_attribute(out_msg, attr);

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_NONCE_REQ);
			break;
		}
		case IMV_ATTESTATION_STATE_NONCE_REQ:
		{
			int min_nonce_len;

			/* Send DH nonce parameters request attribute */
			min_nonce_len = lib->settings->get_int(lib->settings,
						"libimcv.plugins.imv-attestation.min_nonce_len", 0);
			attr = tcg_pts_attr_dh_nonce_params_req_create(min_nonce_len,
													 supported_dh_groups);
			attr->set_noskip_flag(attr, TRUE);
			out_msg->add_attribute(out_msg, attr);

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_TPM_INIT);
			break;
		}
		case IMV_ATTESTATION_STATE_TPM_INIT:
		{
			pts_meas_algorithms_t selected_algorithm;
			chunk_t initiator_value, initiator_nonce;

			if ((pts->get_proto_caps(pts) & PTS_PROTO_CAPS_D))
			{
				/* Send DH nonce finish attribute */
				selected_algorithm = pts->get_meas_algorithm(pts);
				pts->get_my_public_value(pts, &initiator_value, &initiator_nonce);
				attr = tcg_pts_attr_dh_nonce_finish_create(selected_algorithm,
											initiator_value, initiator_nonce);
				attr->set_noskip_flag(attr, TRUE);
				out_msg->add_attribute(out_msg, attr);
			}

			/* Send Get TPM Version attribute */
			attr = tcg_pts_attr_get_tpm_version_info_create();
			attr->set_noskip_flag(attr, TRUE);
			out_msg->add_attribute(out_msg, attr);

			/* Send Get AIK attribute */
			attr = tcg_pts_attr_get_aik_create();
			attr->set_noskip_flag(attr, TRUE);
			out_msg->add_attribute(out_msg, attr);

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_MEAS);
			break;
		}
		case IMV_ATTESTATION_STATE_MEAS:
		{
			enumerator_t *enumerator;
			u_int32_t delimiter = SOLIDUS_UTF;
			char *platform_info, *pathname;
			u_int16_t request_id;
			int id, type;
			bool is_dir, have_request = FALSE;

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
			enumerator = pts_db->create_file_meta_enumerator(pts_db,
															 platform_info);
			if (!enumerator)
			{
				break;
			}
			while (enumerator->enumerate(enumerator, &type, &pathname))
			{
				is_dir = (type != 0);
				DBG2(DBG_IMV, "metadata request for %s '%s'",
					 is_dir ? "directory" : "file", pathname);
				attr = tcg_pts_attr_req_file_meta_create(is_dir, delimiter,
														 pathname);
				attr->set_noskip_flag(attr, TRUE);
				out_msg->add_attribute(out_msg, attr);
				have_request = TRUE;
			}
			enumerator->destroy(enumerator);

			/* Send Request File Measurement attribute */
			enumerator = pts_db->create_file_meas_enumerator(pts_db,
															 platform_info);
			if (!enumerator)
			{
				break;
			}
			while (enumerator->enumerate(enumerator, &id, &type, &pathname))
			{
				is_dir = (type != 0);
				request_id = attestation_state->add_file_meas_request(
							attestation_state, id, is_dir);
				DBG2(DBG_IMV, "measurement request %d for %s '%s'",
					 request_id, is_dir ? "directory" : "file", pathname);
				attr = tcg_pts_attr_req_file_meas_create(is_dir, request_id,
													 delimiter, pathname);
				attr->set_noskip_flag(attr, TRUE);
				out_msg->add_attribute(out_msg, attr);
				have_request = TRUE;
			}
			enumerator->destroy(enumerator);

			/* do we have any file metadata or measurement requests? */
			if (have_request)
			{
				break;
			}
			/* fall through to next state */
		}
		case IMV_ATTESTATION_STATE_COMP_EVID:
		{
			tcg_pts_attr_req_func_comp_evid_t *attr_cast;
			enumerator_t *enumerator;
			pts_component_t *comp;
			pts_comp_func_name_t *comp_name;
			chunk_t keyid;
			int kid, vid, name, qualifier;
			u_int8_t flags;
			u_int32_t depth;
			bool first = TRUE, first_component = TRUE;

			attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_END);

			if (!(pts->get_proto_caps(pts) & PTS_PROTO_CAPS_T) ||
				!(pts->get_proto_caps(pts) & PTS_PROTO_CAPS_D))
			{
				DBG2(DBG_IMV, "PTS-IMC made no TPM available - "
							  "skipping Component Measurements");
				break;
			}
			if (!pts->get_aik_keyid(pts, &keyid))
			{
				DBG1(DBG_IMV, "retrieval of AIK keyid failed");
				return FALSE;
			}
			if (!pts_db)
			{
				DBG1(DBG_IMV, "pts database not available");
				break;
			}
			if (pts_db->check_aik_keyid(pts_db, keyid, &kid) != SUCCESS)
			{
				return FALSE;
			}
			enumerator = pts_db->create_comp_evid_enumerator(pts_db, kid);
			if (!enumerator)
			{
				break;
			}
			while (enumerator->enumerate(enumerator, &vid, &name,
				&qualifier, &depth))
			{
				if (first)
				{
					DBG2(DBG_IMV, "evidence request by");
					first = FALSE;
				}
				comp_name = pts_comp_func_name_create(vid, name, qualifier);
				comp_name->log(comp_name, "  ");

				comp = attestation_state->create_component(attestation_state,
													comp_name, depth, pts_db);
				if (!comp)
				{
					DBG2(DBG_IMV, "    not registered or duplicate"
								  " - removed from request");
					comp_name->destroy(comp_name);
					continue;
				}
				if (first_component)
				{
					attr = tcg_pts_attr_req_func_comp_evid_create();
					attr->set_noskip_flag(attr, TRUE);
					first_component = FALSE;
				}
				flags = comp->get_evidence_flags(comp);
				/* TODO check flags against negotiated_caps */
				attr_cast = (tcg_pts_attr_req_func_comp_evid_t *)attr;
				attr_cast->add_component(attr_cast, flags, depth, comp_name);
			}
			enumerator->destroy(enumerator);

			if (attr)
			{
				/* Send Request Functional Component Evidence attribute */
				out_msg->add_attribute(out_msg, attr);

				/* Send Generate Attestation Evidence attribute */
				attr = tcg_pts_attr_gen_attest_evid_create();
				attr->set_noskip_flag(attr, TRUE);
				out_msg->add_attribute(out_msg, attr);

				attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_EVID_FINAL);
			}
			break;
		}
		case IMV_ATTESTATION_STATE_EVID_FINAL:
			if (attestation_state->components_finalized(attestation_state))
			{
				attestation_state->set_handshake_state(attestation_state,
										IMV_ATTESTATION_STATE_END);
			}
			break;
		case IMV_ATTESTATION_STATE_END:
			break;
	}
	return TRUE;
}
