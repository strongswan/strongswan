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

#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_tpm_version_info.h>
#include <tcg/tcg_pts_attr_aik.h>
#include <tcg/tcg_pts_attr_simple_comp_evid.h>
#include <tcg/tcg_pts_attr_simple_evid_final.h>
#include <tcg/tcg_pts_attr_file_meas.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>
#include <utils/linked_list.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <openssl/sha.h>


/* IMC definitions */

static const char imc_name[] = "Attestation";

#define IMC_VENDOR_ID					PEN_TCG
#define IMC_SUBTYPE						PA_SUBTYPE_TCG_PTS
#define IMC_ATTESTATION_MAX_FILE_SIZE	32768

static imc_agent_t *imc_attestation;


/**
 * Selected Measurement Algorithm, which is selected during
 * the PTS Measurement Algorithm attributes exchange
 * Default value is SHA256
 */
static pts_meas_algorithms_t selected_algorithm = PTS_MEAS_ALGO_SHA256;

/**
 * List of files and directories to measure
 */
static linked_list_t *files, *directories;
 
/**
 * see section 3.7.1 of TCG TNC IF-IMC Specification 1.2
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
	imc_attestation = imc_agent_create(imc_name, IMC_VENDOR_ID, IMC_SUBTYPE,
								imc_id, actual_version);
	if (!imc_attestation)
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
 * Get the TPM Version Information
 */
static TSS_RESULT get_tpm_version_info(BYTE *tpm_version_info)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_RESULT uiResult;
      	UINT32 uiResultLen;
	/* TODO: Needed for parsing version info on IMV side */
	//TPM_CAP_VERSION_INFO versionInfo;
	//UINT64 offset = 0;

	uiResult = Tspi_Context_Create(&hContext);
	if (uiResult != TSS_SUCCESS) {
		DBG1(DBG_IMC,"Error 0x%x on Tspi_Context_Create\n", uiResult);
		return uiResult;
	}
	uiResult = Tspi_Context_Connect(hContext, NULL);
	if (uiResult != TSS_SUCCESS) {
		DBG1(DBG_IMC,"Error 0x%x on Tspi_Context_Connect\n", uiResult);
		return uiResult;
	}
	uiResult = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (uiResult != TSS_SUCCESS) {
		DBG1(DBG_IMC,"Error 0x%x on Tspi_Context_GetTpmObject\n", uiResult);
		return uiResult;
	}

	uiResult = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_VERSION_VAL,  0, NULL, &uiResultLen,
					  &tpm_version_info);
	if (uiResult != TSS_SUCCESS) {
		DBG1(DBG_IMC,"Error 0x%x on Tspi_TPM_GetCapability\n", uiResult);
		return uiResult;
	}
}

/**
 * Get Hash Measurement of a file
 * Uses openssl's sha.h
 */
static TNC_Result hash_file(char *path, unsigned char *out)
{
	BYTE *buffer;
	FILE *file;
	int bytesRead = 0;
	
	file = fopen(path, "rb");
	if (!file) {
		DBG1(DBG_IMC,"File can not be opened %s\n", path);
		return TNC_RESULT_FATAL;
	}
	
	buffer = malloc(IMC_ATTESTATION_MAX_FILE_SIZE);
	if(!buffer)
	{
		DBG1(DBG_IMC,"Buffer couldn't be allocated memory");
		goto fatal;
	}

	switch(selected_algorithm)
	{
		case PTS_MEAS_ALGO_SHA1:
		{
			SHA_CTX sha1;
			SHA1_Init(&sha1);
			
			while((bytesRead = fread(buffer, 1, IMC_ATTESTATION_MAX_FILE_SIZE, file)))
			{
				SHA1_Update(&sha1, buffer, bytesRead);
			}
			SHA1_Final(out, &sha1);
			break;
		}	
		case PTS_MEAS_ALGO_SHA256:
		{
			SHA256_CTX sha256;
			SHA256_Init(&sha256);
			
			while((bytesRead = fread(buffer, 1, IMC_ATTESTATION_MAX_FILE_SIZE, file)))
			{
				SHA256_Update(&sha256, buffer, bytesRead);
			}
			SHA256_Final(out, &sha256);
			break;
		}
		case PTS_MEAS_ALGO_SHA384:
		/*{
			SHA384_CTX sha384;
			SHA384_Init(&sha384);
			
			while((bytesRead = fread(buffer, 1, IMC_ATTESTATION_MAX_FILE_SIZE, file)))
			{
				SHA384_Update(&sha384, buffer, bytesRead);
			}
			SHA384_Final(out, &sha384);
			break;
		}
		*/
		default:
			DBG1(DBG_IMC,"Unsupported Selected Hashing Algorithm \n");
			return TNC_RESULT_FATAL;
	}
	
	fclose(file);
	free(buffer);
	return TNC_RESULT_SUCCESS;
	
fatal:
	fclose(file);
	return TNC_RESULT_FATAL;
}

static TNC_Result send_message(TNC_ConnectionID connection_id)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *attr;
	imc_state_t *state;
	imc_attestation_state_t *attestation_state;
	imc_attestation_handshake_state_t handshake_state;
	TNC_Result result;

	if (!imc_attestation->get_state(imc_attestation, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	attestation_state = (imc_attestation_state_t*)state;
	handshake_state = attestation_state->get_handshake_state(attestation_state);
	
	/* Switch on the attribute type IMC has received */
	switch (handshake_state)
	{
		case IMC_ATTESTATION_STATE_REQ_PROTO_CAP:
		{
			pts_proto_caps_flag_t flags;
			flags = PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_VER;
			attr = tcg_pts_attr_proto_caps_create(flags);
			break;
		}
		case IMC_ATTESTATION_STATE_REQ_MEAS_ALGO:
		{
			pts_meas_algorithms_t algorithm;
			algorithm = PTS_MEAS_ALGO_SHA1;
			/* Save the selected algorithm for further attributes creation */
			selected_algorithm = algorithm;
			attr = tcg_pts_attr_meas_algo_create(algorithm, TRUE);
			break;
		}
		case IMC_ATTESTATION_STATE_GET_TPM_INFO:
		{
			TSS_RESULT uiResult;
			BYTE *tpm_version_info;

			uiResult = get_tpm_version_info(tpm_version_info);
			if (uiResult != TSS_SUCCESS) {
				DBG1(DBG_IMC,"Error 0x%x on get_tpm_version_info\n", uiResult);
				return uiResult;
			}

			attr = tcg_pts_attr_tpm_version_info_create(
				chunk_create((char *)tpm_version_info,
					     strlen(tpm_version_info)));
			break;
		}
		/* TODO: working on */
		/*case IMC_ATTESTATION_STATE_REQ_FILE_MEAS:
		{
			enumerator_t *enumerator;
			measurement_req_entry_t *entry;
			
			enumerator = enumerator_create_single(file_list, NULL);
			while (enumerator->enumerate(enumerator, &entry))
			{
				attr = tcg_pts_attr_req_file_meas_create(false, 
					entry.request_id, delimiter, 
					chunk_create(entry.path,strlen(entry.path)));
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
			}
			
			enumerator = enumerator_create_single(file_list, NULL);
			while (enumerator->enumerate(enumerator, &entry))
			{
				attr = tcg_pts_attr_req_file_meas_create(false, 
					entry.request_id, delimiter, 
					chunk_create(entry.path,strlen(entry.path)));
				attr->set_noskip_flag(attr, TRUE);
				msg->add_attribute(msg, attr);
			}
			break;
		}*/
		case IMC_ATTESTATION_STATE_GET_AIK:
		case IMC_ATTESTATION_STATE_REQ_FUNCT_COMP_EVID:
		case IMC_ATTESTATION_STATE_GEN_ATTEST_EVID:
		case IMC_ATTESTATION_STATE_REQ_FILE_METADATA:
		case IMC_ATTESTATION_STATE_REQ_IML:
		case IMC_ATTESTATION_STATE_INIT:
			DBG1(DBG_IMC, "Attestation IMC has nothing to send: \"%s\"", handshake_state);
			return TNC_RESULT_FATAL;
		default:
			DBG1(DBG_IMC, "Attestation IMC is in unknown state: \"%s\"", handshake_state);
			return TNC_RESULT_FATAL;
	}
	
	
	attr->set_noskip_flag(attr, TRUE);
	msg = pa_tnc_msg_create();
	msg->add_attribute(msg, attr);
	msg->build(msg);
	result = imc_attestation->send_message(imc_attestation, connection_id,
									msg->get_encoding(msg));	
	msg->destroy(msg);

	return result;
}

/**
 * see section 3.7.3 of TCG TNC IF-IMC Specification 1.2
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return send_message(connection_id);
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
	enumerator_t *enumerator;
	TNC_Result result;
	bool fatal_error = FALSE;

	if (!imc_attestation)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imc_attestation->receive_message(imc_attestation, connection_id,
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
			/**
			 * Handle TCG PTS attributes
			 */
			switch(attr->get_type(attr))
			{
				case TCG_PTS_REQ_PROTO_CAPS:
					break;
				case TCG_PTS_MEAS_ALGO:
					break;
				case TCG_PTS_GET_TPM_VERSION_INFO:
					break;
				case TCG_PTS_GET_AIK:
					break;
					
				/* PTS-based Attestation Evidence */
				case TCG_PTS_REQ_FUNCT_COMP_EVID:
					break;
				case TCG_PTS_GEN_ATTEST_EVID:
					break;
				case TCG_PTS_REQ_FILE_MEAS:
					break;
				
				/* TODO: Not implemented yet */
				case TCG_PTS_DH_NONCE_PARAMS_REQ:
				case TCG_PTS_DH_NONCE_FINISH:
				case TCG_PTS_REQ_FILE_META:
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

	/* if no error occurred then always return the same response */
	return fatal_error ? TNC_RESULT_FATAL : send_message(connection_id);
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
