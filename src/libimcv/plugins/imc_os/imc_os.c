/*
 * Copyright (C) 2011-2012 Andreas Steffen
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

#include "imc_os_state.h"

#include <imc/imc_agent.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_assess_result.h>
#include <ietf/ietf_attr_attr_request.h>
#include <ietf/ietf_attr_fwd_enabled.h>
#include <ietf/ietf_attr_installed_packages.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_string_version.h>
#include <os_info/os_info.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <debug.h>

/* IMC definitions */

static const char imc_name[] = "OS";

#define IMC_VENDOR_ID	PEN_IETF
#define IMC_SUBTYPE		PA_SUBTYPE_IETF_OPERATING_SYSTEM

static imc_agent_t *imc_os;
static os_info_t *os;

/**
 * see section 3.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_Initialize(TNC_IMCID imc_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	if (imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has already been initialized", imc_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imc_os = imc_agent_create(imc_name, IMC_VENDOR_ID, IMC_SUBTYPE,
								imc_id, actual_version);
	if (!imc_os)
	{
		return TNC_RESULT_FATAL;
	}

	os = os_info_create();
	if (!os)
	{
		imc_os->destroy(imc_os);
		imc_os = NULL;

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
 * see section 3.8.2 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_NotifyConnectionChange(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_ConnectionState new_state)
{
	imc_state_t *state;

	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imc_os_state_create(connection_id);
			return imc_os->create_state(imc_os, state);
		case TNC_CONNECTION_STATE_HANDSHAKE:
			if (imc_os->change_state(imc_os, connection_id, new_state,
				&state) != TNC_RESULT_SUCCESS)
			{
				return TNC_RESULT_FATAL;
			}
			state->set_result(state, imc_id,
							  TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			return TNC_RESULT_SUCCESS;
		case TNC_CONNECTION_STATE_DELETE:
			return imc_os->delete_state(imc_os, connection_id);
		default:
			return imc_os->change_state(imc_os, connection_id,
											 new_state, NULL);
	}
}

/**
 * Add IETF Product Information attribute to the send queue
 */
static void add_product_info(linked_list_t *attr_list)
{
	pa_tnc_attr_t *attr;

	attr = ietf_attr_product_info_create(PEN_IETF, 0, os->get_name(os));
	attr_list->insert_last(attr_list, attr);
}

/**
 * Add IETF String Version attribute to the send queue
 */
static void add_string_version(linked_list_t *attr_list)
{
	pa_tnc_attr_t *attr;

	attr = ietf_attr_string_version_create(os->get_version(os),
										   chunk_empty, chunk_empty);
	attr_list->insert_last(attr_list, attr);
}

/**
 * Add IETF Forwarding Enabled attribute to the send queue
 */
static void add_fwd_enabled(linked_list_t *attr_list)
{
	pa_tnc_attr_t *attr;
	os_fwd_status_t fwd_status;

	fwd_status = os->get_fwd_status(os);
	DBG1(DBG_IMC, "IPv4 forwarding status: %N",
				   os_fwd_status_names, fwd_status);
	attr = ietf_attr_fwd_enabled_create(fwd_status);
	attr_list->insert_last(attr_list, attr);
}

/**
 * Add an IETF Installed Packages attribute to the send queue
 */
static void add_installed_packages(linked_list_t *attr_list)
{
	pa_tnc_attr_t *attr;
	ietf_attr_installed_packages_t *attr_cast;
	chunk_t libc_name = { "libc-bin", 8 };
	chunk_t libc_version = { "2.15-0ubuntu10.2", 16 };
	chunk_t selinux_name =  { "selinux", 7 };
	chunk_t selinux_version = { "1:0.11", 6 };

	attr = ietf_attr_installed_packages_create();
	attr_cast = (ietf_attr_installed_packages_t*)attr;
	attr_cast->add(attr_cast, libc_name, libc_version);
	attr_cast->add(attr_cast, selinux_name, selinux_version);
	attr_list->insert_last(attr_list, attr);
}

/**
 * see section 3.8.3 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BeginHandshake(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id)
{
	TNC_Result result = TNC_RESULT_SUCCESS;

	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	if (lib->settings->get_bool(lib->settings,
								"libimcv.plugins.imc-os.send_info", TRUE))
	{
		linked_list_t *attr_list;

		attr_list = linked_list_create();
		add_product_info(attr_list);
		add_string_version(attr_list);
		add_fwd_enabled(attr_list);
		result = imc_os->send_message(imc_os, connection_id, FALSE, 0,
									  TNC_IMVID_ANY, attr_list);
		attr_list->destroy(attr_list);
	}

	return result;
}

static TNC_Result receive_message(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id,
								  TNC_UInt32 msg_flags,
								  chunk_t msg,
								  TNC_VendorID msg_vid,
								  TNC_MessageSubtype msg_subtype,
								  TNC_UInt32 src_imv_id,
								  TNC_UInt32 dst_imc_id)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	pen_type_t attr_type;
	linked_list_t *attr_list;
	imc_state_t *state;
	enumerator_t *enumerator;
	TNC_Result result;
	TNC_UInt32 target_imc_id;
	bool fatal_error;

	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}

	/* get current IMC state */
	if (!imc_os->get_state(imc_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}

	/* parse received PA-TNC message and automatically handle any errors */
	result = imc_os->receive_message(imc_os, state, msg, msg_vid,
							msg_subtype, src_imv_id, dst_imc_id, &pa_tnc_msg);

	/* no parsed PA-TNC attributes available if an error occurred */
	if (!pa_tnc_msg)
	{
		return result;
	}
	target_imc_id = (dst_imc_id == TNC_IMCID_ANY) ? imc_id : dst_imc_id;

	/* preprocess any IETF standard error attributes */
	fatal_error = pa_tnc_msg->process_ietf_std_errors(pa_tnc_msg);

	/* analyze PA-TNC attributes */
	attr_list = linked_list_create();
	enumerator = pa_tnc_msg->create_attribute_enumerator(pa_tnc_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		attr_type = attr->get_type(attr);

		if (attr_type.vendor_id != PEN_IETF)
		{
			continue;
		}
		if (attr_type.type == IETF_ATTR_ATTRIBUTE_REQUEST)
		{
			ietf_attr_attr_request_t *attr_cast;
			pen_type_t *entry;
			enumerator_t *e;

			attr_cast = (ietf_attr_attr_request_t*)attr;

			e = attr_cast->create_enumerator(attr_cast);
			while (e->enumerate(e, &entry))
			{
				if (entry->vendor_id != PEN_IETF)
				{
					continue;
				}
				switch (entry->type)
				{
					case IETF_ATTR_PRODUCT_INFORMATION:
						add_product_info(attr_list);
						break;
					case IETF_ATTR_STRING_VERSION:
						add_string_version(attr_list);
						break;
					case IETF_ATTR_FORWARDING_ENABLED:
						add_fwd_enabled(attr_list);
						break;
					case IETF_ATTR_INSTALLED_PACKAGES:
						add_installed_packages(attr_list);
						break;
					default:
						break;
				}
			}
			e->destroy(e); 
		}
		else if (attr_type.type == IETF_ATTR_ASSESSMENT_RESULT)
		{
			ietf_attr_assess_result_t *attr_cast;

			attr_cast = (ietf_attr_assess_result_t*)attr;
			state->set_result(state, target_imc_id,
							  attr_cast->get_result(attr_cast));
		}
	}
	enumerator->destroy(enumerator);
	pa_tnc_msg->destroy(pa_tnc_msg);

	if (fatal_error)
	{
		attr_list->destroy_offset(attr_list, offsetof(pa_tnc_attr_t, destroy));
		return TNC_RESULT_FATAL;
	}

	if (attr_list->get_count(attr_list))
	{
		result = imc_os->send_message(imc_os, connection_id, TRUE, imc_id,
									  src_imv_id, attr_list);
	}
	else
	{
		result = TNC_RESULT_SUCCESS;
	}
	attr_list->destroy(attr_list);

	return result;
}

/**
 * see section 3.8.4 of TCG TNC IF-IMC Specification 1.3

 */
TNC_Result TNC_IMC_ReceiveMessage(TNC_IMCID imc_id,
								  TNC_ConnectionID connection_id,
								  TNC_BufferReference msg,
								  TNC_UInt32 msg_len,
								  TNC_MessageType msg_type)
{
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = msg_type >> 8;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	return receive_message(imc_id, connection_id, 0, chunk_create(msg, msg_len),
						   msg_vid,	msg_subtype, 0, TNC_IMCID_ANY);
}

/**
 * see section 3.8.6 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMC_ReceiveMessageLong(TNC_IMCID imc_id,
									  TNC_ConnectionID connection_id,
									  TNC_UInt32 msg_flags,
									  TNC_BufferReference msg,
									  TNC_UInt32 msg_len,
									  TNC_VendorID msg_vid,
									  TNC_MessageSubtype msg_subtype,
									  TNC_UInt32 src_imv_id,
									  TNC_UInt32 dst_imc_id)
{
	return receive_message(imc_id, connection_id, msg_flags,
						   chunk_create(msg, msg_len), msg_vid, msg_subtype,
						   src_imv_id, dst_imc_id);
}

/**
 * see section 3.8.7 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_BatchEnding(TNC_IMCID imc_id,
							   TNC_ConnectionID connection_id)
{
	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * see section 3.8.8 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_Terminate(TNC_IMCID imc_id)
{
	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	imc_os->destroy(imc_os);
	imc_os = NULL;

	os->destroy(os);
	os = NULL;

	return TNC_RESULT_SUCCESS;
}

/**
 * see section 4.2.8.1 of TCG TNC IF-IMC Specification 1.3
 */
TNC_Result TNC_IMC_ProvideBindFunction(TNC_IMCID imc_id,
									   TNC_TNCC_BindFunctionPointer bind_function)
{
	if (!imc_os)
	{
		DBG1(DBG_IMC, "IMC \"%s\" has not been initialized", imc_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	return imc_os->bind_functions(imc_os, bind_function);
}
