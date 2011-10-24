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

#include "imv_attestation_process.h"

#include <ietf/ietf_attr_pa_tnc_error.h>

#include <pts/pts.h>

#include <tcg/tcg_pts_attr_aik.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_resp.h>
#include <tcg/tcg_pts_attr_file_meas.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_simple_comp_evid.h>
#include <tcg/tcg_pts_attr_simple_evid_final.h>
#include <tcg/tcg_pts_attr_tpm_version_info.h>
#include <tcg/tcg_pts_attr_unix_file_meta.h>

#include <debug.h>
#include <crypto/hashers/hasher.h>

bool imv_attestation_process(pa_tnc_attr_t *attr, linked_list_t *attr_list,
							 imv_attestation_state_t *attestation_state,
							 pts_meas_algorithms_t supported_algorithms,
							 pts_dh_group_t supported_dh_groups,
							 pts_database_t *pts_db,
							 credential_manager_t *pts_credmgr)
{
	chunk_t attr_info;
	pts_t *pts;

	pts = attestation_state->get_pts(attestation_state);
 
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
			if (!(selected_algorithm & supported_algorithms))
			{
				DBG1(DBG_IMV, "PTS-IMC selected unsupported measurement algorithm");
				return FALSE;
			}
			pts->set_meas_algorithm(pts, selected_algorithm);
			break;
		}
		case TCG_PTS_DH_NONCE_PARAMS_RESP:
		{
			tcg_pts_attr_dh_nonce_params_resp_t *attr_cast;
			int nonce_len, min_nonce_len;
			pts_dh_group_t dh_group;
			pts_meas_algorithms_t offered_algorithms, selected_algorithm;
			chunk_t responder_value, responder_nonce;

			attr_cast = (tcg_pts_attr_dh_nonce_params_resp_t*)attr;
			responder_nonce = attr_cast->get_responder_nonce(attr_cast);

			/* check compliance of responder nonce length */
			min_nonce_len = lib->settings->get_int(lib->settings,
						"libimcv.plugins.imv-attestation.min_nonce_len", 0);
			nonce_len = responder_nonce.len;
			if (nonce_len < PTS_MIN_NONCE_LEN ||
			   (min_nonce_len > 0 && nonce_len < min_nonce_len))
			{
				attr = pts_dh_nonce_error_create(
									max(PTS_MIN_NONCE_LEN, min_nonce_len),
										PTS_MAX_NONCE_LEN);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			dh_group = attr_cast->get_dh_group(attr_cast);
			if (!(dh_group & supported_dh_groups))
			{
				DBG1(DBG_IMV, "PTS-IMC selected unsupported DH group");
				return FALSE;
			}

			offered_algorithms = attr_cast->get_hash_algo_set(attr_cast);
			selected_algorithm = pts_meas_algo_select(supported_algorithms,
													  offered_algorithms);
			if (selected_algorithm == PTS_MEAS_ALGO_NONE)
			{
				attr = pts_hash_alg_error_create(supported_algorithms);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			pts->set_dh_hash_algorithm(pts, selected_algorithm);

			if (!pts->create_dh_nonce(pts, dh_group, nonce_len))
			{
				return FALSE;
			}

			responder_value = attr_cast->get_responder_value(attr_cast);
			pts->set_peer_public_value(pts, responder_value,
											responder_nonce);

			/* Calculate secret assessment value */
			if (!pts->calculate_secret(pts))
			{
				return FALSE;
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
		case TCG_PTS_SIMPLE_COMP_EVID:
		{
			tcg_pts_attr_simple_comp_evid_t *attr_cast;
			bool pcr_info_inclided;
			pts_attr_simple_comp_evid_flag_t flags;
			u_int32_t depth, comp_vendor_id, extended_pcr;
			u_int8_t family, measurement_type;
			pts_qualifier_t qualifier;
			pts_funct_comp_name_t name;
			pts_meas_algorithms_t hash_algorithm;
			pts_pcr_transform_t transformation;
			chunk_t measurement_time, policy_uri;
			chunk_t pcr_before, pcr_after, measurement;
					
			attr_cast = (tcg_pts_attr_simple_comp_evid_t*)attr;
			attr_info = attr->get_value(attr);

			pcr_info_inclided = attr_cast->is_pcr_info_included(attr_cast);
			flags = attr_cast->get_flags(attr_cast);
			depth = attr_cast->get_sub_component_depth(attr_cast);
			/* TODO: Implement checking of components with its sub-components */
			if (depth != 0)
			{
				DBG1(DBG_IMV, "Current version of Attestation IMV does not support"
							  "sub component measurement deeper than zero");
			}
			comp_vendor_id = attr_cast->get_spec_comp_funct_name_vendor_id(attr_cast);
			if (comp_vendor_id != PEN_TCG)
			{
				DBG1(DBG_IMV, "Current version of Attestation IMV supports"
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
				DBG1(DBG_IMV, "Wildcard was set for the qualifier "
							  "of functional component");
				return FALSE;
			}
			else if (!qualifier.kernel && !qualifier.sub_component &&
					(qualifier.type & PTS_FUNC_COMP_TYPE_UNKNOWN))
			{
				DBG1(DBG_IMV, "Unknown feature was set for the qualifier "
							  "of functional component");
				return FALSE;
			}
			else
			{
				/* TODO: Implement what todo with received qualifier */
			}
					
			name = attr_cast->get_comp_funct_name(attr_cast);
			measurement_type = attr_cast->get_measurement_type(attr_cast);
			hash_algorithm = attr_cast->get_hash_algorithm(attr_cast);
			transformation = attr_cast->get_pcr_trans(attr_cast);
			measurement_time = attr_cast->get_measurement_time(attr_cast);

			/* Call getters of optional fields when corresponding flag is set */
			if (pcr_info_inclided)
			{
				pcr_entry_t *entry;
				
				extended_pcr = attr_cast->get_extended_pcr(attr_cast);
				pcr_before = attr_cast->get_pcr_before_value(attr_cast);
				pcr_after = attr_cast->get_pcr_after_value(attr_cast);
				measurement = attr_cast->get_comp_measurement(attr_cast);

				DBG4(DBG_IMV,"PCR: %d was extended with %B", extended_pcr, &measurement);
				DBG4(DBG_IMV,"PCR: %d before value: %B", extended_pcr, &pcr_before);
				DBG4(DBG_IMV,"PCR: %d after value: %B", extended_pcr, &pcr_after);

				entry = malloc_thing(pcr_entry_t);
				entry->pcr_number = extended_pcr;
				strcpy(entry->pcr_value, pcr_after.ptr);
				pts->add_pcr_entry(pts, entry);
				
			}
			if (flags != PTS_SIMPLE_COMP_EVID_FLAG_NO_VALID)
			{
				policy_uri = attr_cast->get_policy_uri(attr_cast);
			}
					
			/** TODO: Implement saving the PCR number, Hash Algo = communicated one,
			 * PCR transform (truncate SHA256, SHA384), PCR before and after values
			 */
			break;
		}
		case TCG_PTS_SIMPLE_EVID_FINAL:
		{
			tcg_pts_attr_simple_evid_final_t *attr_cast;
			pts_simple_evid_final_flag_t flags;
			chunk_t pcr_comp;
			chunk_t tpm_quote_sign;
			chunk_t evid_sign;
			bool evid_signature_included;
					
			/** TODO: Ignoring Composite Hash Algorithm field
			 * No flag defined which indicates the precense of it
			 */
			attr_cast = (tcg_pts_attr_simple_evid_final_t*)attr;
			evid_signature_included = attr_cast->is_evid_sign_included(attr_cast);
			flags = attr_cast->get_flags(attr_cast);

			if ((flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2) ||
				(flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2_CAP_VER))
			{
				DBG1(DBG_IMV, "This version of Attestation IMV can not handle"
					 " TPM Quote Info2 structure");
				break;
			}
			if (flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO)
			{
				chunk_t pcr_composite, quote_info, quote_digest;
				hasher_t *hasher;
				pcr_comp = attr_cast->get_pcr_comp(attr_cast);
				tpm_quote_sign = attr_cast->get_tpm_quote_sign(attr_cast);

				/* Construct PCR Composite and TPM Quote Info structures*/
				if (!pts->get_quote_info(pts, &pcr_composite, &quote_info))
				{
					DBG1(DBG_IMV, "unable to contruct TPM Quote Info");
					return FALSE;
				}

				/* Check calculated PCR composite structure matches with received */
				if (pcr_comp.ptr && !chunk_equals(pcr_comp, pcr_composite))
				{
					DBG1(DBG_IMV, "received PCR Compsosite didn't match with constructed");
					free(pcr_composite.ptr);
					free(quote_info.ptr);
					return FALSE;
				}
				free(pcr_composite.ptr);
				
				/* SHA1(TPM Quote Info) expected from IMC */
				hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
				hasher->allocate_hash(hasher, quote_info, &quote_digest);
				hasher->destroy(hasher);
				
				if (tpm_quote_sign.ptr &&
					!pts->verify_quote_signature(pts, quote_digest, tpm_quote_sign))
				{
					free(quote_digest.ptr);
					free(quote_info.ptr);
					return FALSE;
				}
				DBG2(DBG_IMV, "signature verification succeeded for TPM Quote Info");
				free(quote_digest.ptr);
				free(quote_info.ptr);
			}
			
			if (evid_signature_included)
			{
				/** TODO: What to do with Evidence Signature */
				evid_sign = attr_cast->get_evid_sign(attr_cast);
				DBG1(DBG_IMV, "This version of Attestation IMV can not handle"
					 " Optional Evidence Signature field");
			}

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
				attestation_state->set_measurement_error(attestation_state);
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
	return TRUE;
}

