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
#include "imv_os_database.h"

#include <imv/imv_agent.h>
#include <imv/imv_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_attr_request.h>
#include <ietf/ietf_attr_default_pwd_enabled.h>
#include <ietf/ietf_attr_fwd_enabled.h>
#include <ietf/ietf_attr_installed_packages.h>
#include <ietf/ietf_attr_numeric_version.h>
#include <ietf/ietf_attr_op_status.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_remediation_instr.h>
#include <ietf/ietf_attr_string_version.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_get_settings.h>
#include <ita/ita_attr_settings.h>
#include <ita/ita_attr_angel.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <collections/linked_list.h>
#include <utils/debug.h>
#include <utils/lexparser.h>

/* IMV definitions */

static const char imv_name[] = "OS";

static pen_type_t msg_types[] = {
	{ PEN_IETF, PA_SUBTYPE_IETF_OPERATING_SYSTEM }
};

static imv_agent_t *imv_os;

/**
 * IMV OS database
 */
static imv_os_database_t *os_db;

/*
 * see section 3.8.1 of TCG TNC IF-IMV Specification 1.3
 */
TNC_Result TNC_IMV_Initialize(TNC_IMVID imv_id,
							  TNC_Version min_version,
							  TNC_Version max_version,
							  TNC_Version *actual_version)
{
	char *uri;

	if (imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has already been initialized", imv_name);
		return TNC_RESULT_ALREADY_INITIALIZED;
	}
	imv_os = imv_agent_create(imv_name, msg_types, countof(msg_types),
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

	/* attach OS database */
	uri = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-os.database", NULL);
	if (uri)
	{
		os_db = imv_os_database_create(uri);
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

static TNC_Result receive_message(imv_state_t *state, imv_msg_t *in_msg)
{
	imv_msg_t *out_msg;
	imv_os_state_t *os_state;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t type;
	TNC_Result result;
	chunk_t os_name = chunk_empty;
	chunk_t os_version = chunk_empty;
	bool fatal_error = FALSE, assessment = FALSE;
	char non_market_apps_str[] = "install_non_market_apps";
	char android_id_str[] = "android_id";
	char machine_id_str[] = "/var/lib/dbus/machine-id";

	os_state = (imv_os_state_t*)state;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	out_msg = imv_msg_create_as_reply(in_msg);

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF)
		{
			switch (type.type)
			{
				case IETF_ATTR_PRODUCT_INFORMATION:
				{
					ietf_attr_product_info_t *attr_cast;
					pen_t vendor_id;

					attr_cast = (ietf_attr_product_info_t*)attr;
					os_name = attr_cast->get_info(attr_cast, &vendor_id, NULL);
					if (vendor_id != PEN_IETF)
					{
						DBG1(DBG_IMV, "operating system name is '%.*s' "
									  "from vendor %N", os_name.len, os_name.ptr,
									   pen_names, vendor_id);
					}
					else
					{
						DBG1(DBG_IMV, "operating system name is '%.*s'",
									   os_name.len, os_name.ptr);
					}
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
				case IETF_ATTR_NUMERIC_VERSION:
				{
					ietf_attr_numeric_version_t *attr_cast;
					u_int32_t major, minor;

					attr_cast = (ietf_attr_numeric_version_t*)attr;
					attr_cast->get_version(attr_cast, &major, &minor);
					DBG1(DBG_IMV, "operating system numeric version is %d.%d",
								   major, minor);
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
					if (fwd_status == OS_FWD_ENABLED)
					{
						os_state->set_os_settings(os_state,
											OS_SETTINGS_FWD_ENABLED);
					}
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
					if (default_pwd_status)
					{
						os_state->set_os_settings(os_state,
											OS_SETTINGS_DEFAULT_PWD_ENABLED);
					}
					break;
				}
				case IETF_ATTR_INSTALLED_PACKAGES:
				{
					ietf_attr_installed_packages_t *attr_cast;
					enumerator_t *e;
					status_t status;

					/* Received at least one Installed Packages attribute */
					os_state->set_package_request(os_state, FALSE);

					if (!os_db)
					{
						break;
					}
					attr_cast = (ietf_attr_installed_packages_t*)attr;

					e = attr_cast->create_enumerator(attr_cast);
					status = os_db->check_packages(os_db, os_state, e);
					e->destroy(e);

					if (status == FAILED)
					{
						state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
						assessment = TRUE;
					}
					break;
				}
				default:
					break;
			}
		}
		else if (type.vendor_id == PEN_ITA)
		{
			switch (type.type)
			{
				case ITA_ATTR_SETTINGS:
				{
					ita_attr_settings_t *attr_cast;
					enumerator_t *e;
					char *name;
					chunk_t value;

					attr_cast = (ita_attr_settings_t*)attr;
					e = attr_cast->create_enumerator(attr_cast);
					while (e->enumerate(e, &name, &value))
					{
						if (streq(name, non_market_apps_str) &&
							chunk_equals(value, chunk_from_chars('1')))
						{
							os_state->set_os_settings(os_state,
												OS_SETTINGS_NON_MARKET_APPS);
						}
						else if ((streq(name, android_id_str) ||
								  streq(name, machine_id_str)) && os_db)
						{
							os_state->set_device_id(os_state,
										os_db->get_device_id(os_db, value));
						}
						DBG1(DBG_IMV, "setting '%s'\n  %.*s",
							 name, value.len, value.ptr);
					}
					e->destroy(e);
					break;
				}
				case ITA_ATTR_START_ANGEL:
					os_state->set_angel_count(os_state, TRUE);
					break;
				case ITA_ATTR_STOP_ANGEL:
					os_state->set_angel_count(os_state, FALSE);
					break;
				default:
					break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (os_name.len && os_version.len)
	{
		os_type_t os_type;
		ita_attr_get_settings_t *attr_cast;

		/* set the OS type, name and version */
		os_type = os_type_from_name(os_name);
		os_state->set_info(os_state,os_type, os_name, os_version);

		/* requesting installed packages */
		os_state->set_package_request(os_state, TRUE);
		attr = ietf_attr_attr_request_create(PEN_IETF,
											 IETF_ATTR_INSTALLED_PACKAGES);
		out_msg->add_attribute(out_msg, attr);

		/* requesting Android or Linux settings */
		attr = ita_attr_get_settings_create();
		attr_cast = (ita_attr_get_settings_t*)attr;

		if (os_type == OS_TYPE_ANDROID)
		{
			attr_cast->add(attr_cast, android_id_str);
			attr_cast->add(attr_cast, non_market_apps_str);
		}
		else
		{
			attr_cast->add(attr_cast, machine_id_str);
			attr_cast->add(attr_cast, "/proc/sys/kernel/tainted");
		}
		out_msg->add_attribute(out_msg, attr);
	}

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		assessment = TRUE;
	}

	/* If all Installed Packages attributes were received, go to assessment */
	if (!assessment &&
		!os_state->get_package_request(os_state) &&
		!os_state->get_angel_count(os_state))
	{
		int device_id, count, count_update, count_blacklist, count_ok;
		u_int os_settings;

		os_settings = os_state->get_os_settings(os_state);
		os_state->get_count(os_state, &count, &count_update, &count_blacklist,
									  &count_ok);
		DBG1(DBG_IMV, "processed %d packages: %d not updated, %d blacklisted, "
			 "%d ok, %d not found", count, count_update, count_blacklist,
			 count_ok, count - count_update - count_blacklist - count_ok);

		/* Store device information in database */
		device_id = os_state->get_device_id(os_state);
		if (os_db && device_id)
		{
			os_db->set_device_info(os_db, device_id,
						os_state->get_info(os_state, NULL, NULL, NULL),
						count, count_update, count_blacklist, os_settings);
		}

		if (count_update || count_blacklist || os_settings)
		{
			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
								TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR);
		}
		else
		{
			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_COMPLIANT);
		}
		assessment = TRUE;
	}

	if (assessment)
	{
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}  
		return imv_os->provide_recommendation(imv_os, state);
	}

	/* send PA-TNC message with excl flag set */ 
	result = out_msg->send(out_msg, TRUE);
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

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_data(imv_os, state, connection_id, msg_type,
									  chunk_create(msg, msg_len));
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

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(imv_os, state, connection_id,
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

	if (!imv_os)
	{
		DBG1(DBG_IMV, "IMV \"%s\" has not been initialized", imv_name);
		return TNC_RESULT_NOT_INITIALIZED;
	}
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return imv_os->provide_recommendation(imv_os, state);
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
	if (!imv_os->get_state(imv_os, connection_id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	os_state = (imv_os_state_t*)state;

	if (os_state->get_info(os_state, NULL, NULL, NULL) == NULL)
	{
		imv_msg_t *out_msg;
		pa_tnc_attr_t *attr;
		ietf_attr_attr_request_t *attr_cast;

		out_msg = imv_msg_create(imv_os, state, connection_id, imv_id,
								 TNC_IMCID_ANY, msg_types[0]);
		attr = ietf_attr_attr_request_create(PEN_IETF,
											 IETF_ATTR_PRODUCT_INFORMATION);
		attr_cast = (ietf_attr_attr_request_t*)attr;
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_STRING_VERSION);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_NUMERIC_VERSION);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_OPERATIONAL_STATUS);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_FORWARDING_ENABLED);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED);
		out_msg->add_attribute(out_msg, attr);

		/* send PA-TNC message with excl flag not set */
		result = out_msg->send(out_msg, FALSE);
		out_msg->destroy(out_msg);
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
	DESTROY_IF(os_db);

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
