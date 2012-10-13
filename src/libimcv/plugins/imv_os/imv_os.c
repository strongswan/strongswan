/*
 * Copyright (C) 2012 Andreas Steffen
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

#include "imv_os_state.h"

#include <imv/imv_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_attr_request.h>
#include <ietf/ietf_attr_default_pwd_enabled.h>
#include <ietf/ietf_attr_fwd_enabled.h>
#include <ietf/ietf_attr_installed_packages.h>
#include <ietf/ietf_attr_op_status.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_string_version.h>
#include <os_info/os_info.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/linked_list.h>
#include <debug.h>

/* IMV definitions */

static const char imv_name[] = "OS";

#define IMV_VENDOR_ID	PEN_IETF
#define IMV_SUBTYPE		PA_SUBTYPE_IETF_OPERATING_SYSTEM

static imv_agent_t *imv_os;

/*
 * see section 3.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imv_os = imv_agent_create(imv_name, IMV_VENDOR_ID, IMV_SUBTYPE,
								imv_id, actual_version);
	if (!imv_os)
	{
		return TNC_RESULT_FATAL;
	}
	if (min_version > TNC_IFIMV_VERSION_1 || max_version < TNC_IFIMV_VERSION_1)
	{
		DBG1(DBG_IMV, "no common IF-IMV version");
		return TNC_RESULT_NO_COMMON_VERSION;
	}

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

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_os_state_create(connection_id);
			return imv_os->create_state(imv_os, state);
		case TNC_CONNECTION_STATE_DELETE:
			return imv_os->delete_state(imv_os, connection_id);
		default:
			return imv_os->change_state(imv_os, connection_id,
											 new_state, NULL);
	}
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
	imv_os_state_t *os_state;
	enumerator_t *enumerator;
	TNC_Result result;
	chunk_t os_name = chunk_empty;
	chunk_t os_version = chunk_empty;
	bool fatal_error, assessment = FALSE;

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMV state */
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	os_state = (imv_os_state_t*)state;

	/* parse received PA-TNC message and automatically handle any errors */ 
	result = imv_os->receive_message(imv_os, state, msg, msg_vid,
					 		msg_subtype, src_imc_id, dst_imv_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}

	/* preprocess any IETF standard error attributes */
	fatal_error = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg);

	/* analyze PA-TNC attributes */
	attr_list = linked_list_create();
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id != PEN_IETF)
		{
			continue;
		}
		switch (type.type)
		{
			case IETF_ATTR_PRODUCT_INFORMATION:
			{
				ietf_attr_product_info_t *attr_cast;

				attr_cast = (ietf_attr_product_info_t*)attr;
				os_name = attr_cast->get_info(attr_cast, NULL, NULL);
				DBG1(DBG_IMV, "operating system name is '%.*s'",
							   os_name.len, os_name.ptr);
				break;
			}
			case IETF_ATTR_STRING_VERSION:
			{
				ietf_attr_string_version_t *attr_cast;

				attr_cast = (ietf_attr_string_version_t*)attr;
				os_version = attr_cast->get_version(attr_cast, NULL, NULL);
				if (os_version.len)
				{
					DBG1(DBG_IMV, "operating system version is '%.*s'",
								   os_version.len, os_version.ptr);
				}
				break;
			}
			case IETF_ATTR_OPERATIONAL_STATUS:
			{
				ietf_attr_op_status_t *attr_cast;
				op_status_t op_status;
				op_result_t op_result;
				time_t last_boot;

				attr_cast = (ietf_attr_op_status_t*)attr;
				op_status = attr_cast->get_status(attr_cast);
				op_result = attr_cast->get_result(attr_cast);
				last_boot = attr_cast->get_last_use(attr_cast);
				DBG1(DBG_IMV, "operational status: %N, result: %N",
					 op_status_names, op_status, op_result_names, op_result);
				DBG1(DBG_IMV, "last boot: %T", &last_boot, TRUE);
				break;
			}
			case IETF_ATTR_FORWARDING_ENABLED:
			{
				ietf_attr_fwd_enabled_t *attr_cast;
				os_fwd_status_t fwd_status;

				attr_cast = (ietf_attr_fwd_enabled_t*)attr;
				fwd_status = attr_cast->get_status(attr_cast);
				DBG1(DBG_IMV, "IPv4 forwarding status: %N",
							   os_fwd_status_names, fwd_status);
				break;
			}
			case IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED:
			{
				ietf_attr_default_pwd_enabled_t *attr_cast;
				bool default_pwd_status;

				attr_cast = (ietf_attr_default_pwd_enabled_t*)attr;
				default_pwd_status = attr_cast->get_status(attr_cast);
				DBG1(DBG_IMV, "factory default password: %sabled",
							   default_pwd_status ? "en":"dis");
				break;
			}
			case IETF_ATTR_INSTALLED_PACKAGES:
			{ 
				ietf_attr_installed_packages_t *attr_cast;
				enumerator_t *e;
				chunk_t name, version;

				attr_cast = (ietf_attr_installed_packages_t*)attr;
				e = attr_cast->create_enumerator(attr_cast);
				while (e->enumerate(e, &name, &version))
				{
					DBG1(DBG_IMV, "package '%.*s' %.*s", name.len, name.ptr,
								   version.len, version.ptr);
				}
				e->destroy(e);

				state->set_recommendation(state,
									  TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
									  TNC_IMV_EVALUATION_RESULT_COMPLIANT);	
				assessment = TRUE;
				break;
			}
			default:
				break;
		}		
	}
	enumerator->destroy(enumerator);

	if (os_name.len && os_version.len)
	{
		char *product_info;

		os_state->set_info(os_state, os_name, os_version);
		product_info = os_state->get_info(os_state);

		if (streq(product_info, "Windows 1.2.3"))
		{
			DBG1(DBG_IMV, "OS '%s' is not supported", product_info);

			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR);
			assessment = TRUE;
		}
		else
		{	
			DBG1(DBG_IMV, "requesting installed packages for '%s'",
						   product_info);
			attr = ietf_attr_attr_request_create(PEN_IETF,
								IETF_ATTR_INSTALLED_PACKAGES);
			attr_list->insert_last(attr_list, attr);
		}
	}
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		assessment = TRUE;
	}

	if (assessment)
	{
		attr_list->destroy_offset(attr_list, offsetof(pa_tnc_attr_t, destroy));
		return imv_os->provide_recommendation(imv_os, connection_id, src_imc_id);
	}

	result = imv_os->send_message(imv_os, connection_id, TRUE, imv_id,
								  src_imc_id, attr_list);
	attr_list->destroy(attr_list);

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
	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_os->provide_recommendation(imv_os, connection_id,
											   TNC_IMCID_ANY);
}

/**
 * see section 3.8.8 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_BatchEnding(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id)
{
	imv_state_t *state;
	imv_os_state_t *os_state;
	TNC_Result result = TNC_RESULT_SUCCESS;

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMV state */
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	os_state = (imv_os_state_t*)state;

	if (os_state->get_info(os_state) == NULL)
	{
		pa_tnc_attr_t *attr;
		linked_list_t *attr_list;
		ietf_attr_attr_request_t *attr_cast;

		attr_list = linked_list_create();
		attr = ietf_attr_attr_request_create(PEN_IETF,
											 IETF_ATTR_PRODUCT_INFORMATION);
		attr_cast = (ietf_attr_attr_request_t*)attr;
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_STRING_VERSION);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_OPERATIONAL_STATUS);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_FORWARDING_ENABLED);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED);
		attr_list->insert_last(attr_list, attr);
		result = imv_os->send_message(imv_os, connection_id, FALSE, imv_id,
									  TNC_IMCID_ANY, attr_list);
		attr_list->destroy(attr_list);
	}

	return result;
}

/**
 * see section 3.8.9 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Terminate(TNC_IMVID imv_id)
{
	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imv_os->destroy(imv_os);
	imv_os = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_ProvideBindFunction(TNC_IMVID imv_id,
									   TNC_TNCS_BindFunctionPointer bind_function)
{
	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imv_os->bind_functions(imv_os, bind_function);
}
