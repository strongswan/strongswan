/*
 * Copyright (C) 2011 Andreas Steffen
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

#include "pa_tnc_attr.h"
#include "ietf/ietf_attr.h"
#include "ietf/ietf_attr_pa_tnc_error.h"
#include "ietf/ietf_attr_port_filter.h"
#include "tcg/tcg_attr.h"
#include "tcg/tcg_pts_attr_req_proto_caps.h"
#include "tcg/tcg_pts_attr_proto_caps.h"
#include "tcg/tcg_pts_attr_meas_algo.h"
#include "tcg/tcg_pts_attr_get_tpm_version_info.h"
#include "tcg/tcg_pts_attr_tpm_version_info.h"
#include "tcg/tcg_pts_attr_get_aik.h"
#include "tcg/tcg_pts_attr_aik.h"
#include "tcg/tcg_pts_attr_req_funct_comp_evid.h"
#include "tcg/tcg_pts_attr_gen_attest_evid.h"
#include "tcg/tcg_pts_attr_simple_comp_evid.h"
#include "tcg/tcg_pts_attr_simple_evid_final.h"
#include "tcg/tcg_pts_attr_req_file_meas.h"
#include "tcg/tcg_pts_attr_file_meas.h"
#include "ita/ita_attr_command.h"

/**
 * See header
 */
pa_tnc_attr_t* pa_tnc_attr_create_create_from_data(pen_t vendor_id, u_int32_t type,
											chunk_t value)
{
	switch (vendor_id)
	{
		case PEN_IETF:
			switch (type)
			{
				case IETF_ATTR_PORT_FILTER:
					return ietf_attr_port_filter_create_from_data(value);
				case IETF_ATTR_PA_TNC_ERROR:
					return ietf_attr_pa_tnc_error_create_from_data(value);
				case IETF_ATTR_TESTING:
				case IETF_ATTR_ATTRIBUTE_REQUEST:
				case IETF_ATTR_PRODUCT_INFORMATION:
				case IETF_ATTR_NUMERIC_VERSION:
				case IETF_ATTR_STRING_VERSION:
				case IETF_ATTR_OPERATIONAL_STATUS:
				case IETF_ATTR_INSTALLED_PACKAGES:
				case IETF_ATTR_ASSESSMENT_RESULT:
				case IETF_ATTR_REMEDIATION_INSTRUCTIONS:
				case IETF_ATTR_FORWARDING_ENABLED:
				case IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED:
				case IETF_ATTR_RESERVED:
				default:
					break;
			}
			break;
		case PEN_TCG:
			switch (type)
			{
				case TCG_PTS_REQ_PROTO_CAPS:
					return tcg_pts_attr_req_proto_caps_create_from_data(value);
				case TCG_PTS_PROTO_CAPS:
					return tcg_pts_attr_proto_caps_create_from_data(value);
				case TCG_PTS_MEAS_ALGO:
					return tcg_pts_attr_meas_algo_create_from_data(value, FALSE);
				case TCG_PTS_MEAS_ALGO_SELECTION:
					return tcg_pts_attr_meas_algo_create_from_data(value, TRUE);
				case TCG_PTS_GET_TPM_VERSION_INFO:
					return tcg_pts_attr_get_tpm_version_info_create_from_data(value);
				case TCG_PTS_TPM_VERSION_INFO:
					return tcg_pts_attr_tpm_version_info_create_from_data(value);
				case TCG_PTS_GET_AIK:
					return tcg_pts_attr_get_aik_create_from_data(value);
				case TCG_PTS_AIK:
					return tcg_pts_attr_aik_create_from_data(value);
				case TCG_PTS_REQ_FUNCT_COMP_EVID:
					return tcg_pts_attr_req_funct_comp_evid_create_from_data(value);
				case TCG_PTS_GEN_ATTEST_EVID:
					return tcg_pts_attr_gen_attest_evid_create_from_data(value);
				case TCG_PTS_SIMPLE_COMP_EVID:
					return tcg_pts_attr_simple_comp_evid_create_from_data(value);
				case TCG_PTS_SIMPLE_EVID_FINAL:
					return tcg_pts_attr_simple_evid_final_create_from_data(value);
				case TCG_PTS_REQ_FILE_MEAS:
					return tcg_pts_attr_req_file_meas_create_from_data(value);
				case TCG_PTS_FILE_MEAS:
					return tcg_pts_attr_file_meas_create_from_data(value);
				case TCG_PTS_DH_NONCE_PARAMS_REQ:
				case TCG_PTS_DH_NONCE_PARAMS_RESP:
				case TCG_PTS_DH_NONCE_FINISH:
				case TCG_PTS_REQ_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_TEMPL_REF_MANI_SET_META:
				case TCG_PTS_UPDATE_TEMPL_REF_MANI:
				case TCG_PTS_VERIFICATION_RESULT:
				case TCG_PTS_INTEG_REPORT:
				case TCG_PTS_REQ_FILE_META:
				case TCG_PTS_WIN_FILE_META:
				case TCG_PTS_UNIX_FILE_META:
				case TCG_PTS_REQ_REGISTRY_VALUE:
				case TCG_PTS_REGISTRY_VALUE:
				case TCG_PTS_REQ_INTEG_MEAS_LOG:
				case TCG_PTS_INTEG_MEAS_LOG:
				default:
					break;
			}
			break;
		case PEN_ITA:
			switch (type)
			{
				case ITA_ATTR_COMMAND:
					return ita_attr_command_create_from_data(value);
				default:
					break;
			}
			break;
		default:
			break;
	}
	return NULL;
}
