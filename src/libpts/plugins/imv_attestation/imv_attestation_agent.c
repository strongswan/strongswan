/*
 * Copyright (C) 2011-2012 Sansar Choinyambuu
 * Copyright (C) 2011-2013 Andreas Steffen
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

#include "imv_attestation_agent.h"
#include "imv_attestation_state.h"
#include "imv_attestation_process.h"
#include "imv_attestation_build.h"

#include <imcv.h>
#include <imv/imv_agent.h>
#include <imv/imv_msg.h>
#include <ietf/ietf_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ietf/ietf_attr_product_info.h>
#include <ietf/ietf_attr_string_version.h>

#include <libpts.h>

#include <pts/pts.h>
#include <pts/pts_database.h>
#include <pts/pts_creds.h>

#include <tcg/tcg_attr.h>

#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/debug.h>
#include <credentials/credential_manager.h>
#include <collections/linked_list.h>

typedef struct private_imv_attestation_agent_t private_imv_attestation_agent_t;

/* Subscribed PA-TNC message subtypes */
static pen_type_t msg_types[] = {
	{ PEN_TCG,  PA_SUBTYPE_TCG_PTS },
	{ PEN_IETF, PA_SUBTYPE_IETF_OPERATING_SYSTEM }
};

/**
 * Private data of an imv_attestation_agent_t object.
 */
struct private_imv_attestation_agent_t {

	/**
	 * Public members of imv_attestation_agent_t
	 */
	imv_agent_if_t public;

	/**
	 * IMV agent responsible for generic functions
	 */
	imv_agent_t *agent;

	/**
	 * Supported PTS measurement algorithms
	 */
	pts_meas_algorithms_t supported_algorithms;

	/**
	 * Supported PTS Diffie Hellman Groups
	 */
	pts_dh_group_t supported_dh_groups;

	/**
	 * PTS file measurement database
	 */
	pts_database_t *pts_db;

	/**
	 * PTS credentials
	 */
	pts_creds_t *pts_creds;

	/**
	 * PTS credential manager
	 */
	credential_manager_t *pts_credmgr;

};

METHOD(imv_agent_if_t, bind_functions, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_TNCS_BindFunctionPointer bind_function)
{
	return this->agent->bind_functions(this->agent, bind_function);
}

METHOD(imv_agent_if_t, notify_connection_change, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_ConnectionID id,
	TNC_ConnectionState new_state)
{
	imv_state_t *state;

	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_attestation_state_create(id);
			return this->agent->create_state(this->agent, state);
		case TNC_CONNECTION_STATE_DELETE:
			return this->agent->delete_state(this->agent, id);
		default:
			return this->agent->change_state(this->agent, id, new_state, NULL);
	}
}

/**
 * Build a message to be sent
 */
static TNC_Result send_message(private_imv_attestation_agent_t *this,
							   imv_state_t *state, imv_msg_t *out_msg)
{
	imv_attestation_state_t *attestation_state;
	TNC_Result result;

	attestation_state = (imv_attestation_state_t*)state;

	if (imv_attestation_build(out_msg, attestation_state,
							  this->supported_algorithms,
							  this->supported_dh_groups, this->pts_db))
	{
		result = out_msg->send(out_msg, TRUE);
	}
	else
	{
		result = TNC_RESULT_FATAL;
	}

	return result;
}

/**
 * Process a received message
 */
static TNC_Result receive_msg(private_imv_attestation_agent_t *this,
							  imv_state_t *state, imv_msg_t *in_msg)
{
	imv_attestation_state_t *attestation_state;
	imv_msg_t *out_msg;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t type;
	TNC_Result result;
	pts_t *pts;
	chunk_t os_name = chunk_empty;
	chunk_t os_version = chunk_empty;
	bool fatal_error = FALSE;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	attestation_state = (imv_attestation_state_t*)state;
	pts = attestation_state->get_pts(attestation_state);

	out_msg = imv_msg_create_as_reply(in_msg);
	out_msg->set_msg_type(out_msg, msg_types[0]);

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF)
		{
			switch (type.type)
			{
				case IETF_ATTR_PA_TNC_ERROR:
				{
					ietf_attr_pa_tnc_error_t *error_attr;
					pen_type_t error_code;
					chunk_t msg_info;

					error_attr = (ietf_attr_pa_tnc_error_t*)attr;
					error_code = error_attr->get_error_code(error_attr);

					if (error_code.vendor_id == PEN_TCG)
					{
						msg_info = error_attr->get_msg_info(error_attr);

						DBG1(DBG_IMV, "received TCG-PTS error '%N'",
							 pts_error_code_names, error_code.type);
						DBG1(DBG_IMV, "error information: %B", &msg_info);

						result = TNC_RESULT_FATAL;
					}
					break;
				}
				case IETF_ATTR_PRODUCT_INFORMATION:
				{
					ietf_attr_product_info_t *attr_cast;

					attr_cast = (ietf_attr_product_info_t*)attr;
					os_name = attr_cast->get_info(attr_cast, NULL, NULL);
					break;
				}
				case IETF_ATTR_STRING_VERSION:
				{
					ietf_attr_string_version_t *attr_cast;

					attr_cast = (ietf_attr_string_version_t*)attr;
					os_version = attr_cast->get_version(attr_cast, NULL, NULL);
					break;
				}
				default:
					break;
			}
		}
		else if (type.vendor_id == PEN_TCG)
		{
			if (!imv_attestation_process(attr, out_msg, attestation_state, 
				this->supported_algorithms, this->supported_dh_groups,
				this->pts_db, this->pts_credmgr))
			{
				result = TNC_RESULT_FATAL;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (os_name.len && os_version.len)
	{
		pts->set_platform_info(pts, os_name, os_version);
	}

	if (fatal_error || result != TNC_RESULT_SUCCESS)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}

	/* send PA-TNC message with excl flag set */
	result = out_msg->send(out_msg, TRUE);

	if (result != TNC_RESULT_SUCCESS)
	{
		out_msg->destroy(out_msg);
		return result;
	}

	/* check the IMV state for the next PA-TNC attributes to send */
	result = send_message(this, state, out_msg);

	if (result != TNC_RESULT_SUCCESS)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}

	if (attestation_state->get_handshake_state(attestation_state) ==
		IMV_ATTESTATION_STATE_END)
	{
		if (attestation_state->get_file_meas_request_count(attestation_state))
		{
			DBG1(DBG_IMV, "failure due to %d pending file measurements",
				attestation_state->get_file_meas_request_count(attestation_state));
			attestation_state->set_measurement_error(attestation_state,
								IMV_ATTESTATION_ERROR_FILE_MEAS_PEND);
		}
		if (attestation_state->get_measurement_error(attestation_state))
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
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}
	out_msg->destroy(out_msg);

	return result;

}

METHOD(imv_agent_if_t, receive_message, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_ConnectionID id,
	TNC_MessageType msg_type, chunk_t msg)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_data(this->agent, state, id, msg_type, msg);
	result = receive_msg(this, state, in_msg);
	in_msg->destroy(in_msg);

	return result;
}

METHOD(imv_agent_if_t, receive_message_long, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_ConnectionID id,
	TNC_UInt32 src_imc_id, TNC_UInt32 dst_imv_id,
	TNC_VendorID msg_vid, TNC_MessageSubtype msg_subtype, chunk_t msg)
{
	imv_state_t *state;
	imv_msg_t *in_msg;
	TNC_Result result;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	in_msg = imv_msg_create_from_long_data(this->agent, state, id,
					src_imc_id, dst_imv_id, msg_vid, msg_subtype, msg);
	result = receive_msg(this, state, in_msg);
	in_msg->destroy(in_msg);

	return result;

}

METHOD(imv_agent_if_t, batch_ending, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_ConnectionID id)
{
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_if_t, solicit_recommendation, TNC_Result,
	private_imv_attestation_agent_t *this, TNC_ConnectionID id)
{
	imv_state_t *state;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return this->agent->provide_recommendation(this->agent, state);
}

METHOD(imv_agent_if_t, destroy, void,
	private_imv_attestation_agent_t *this)
{
	if (this->pts_creds)
	{
		this->pts_credmgr->remove_set(this->pts_credmgr,
						 			  this->pts_creds->get_set(this->pts_creds));
		this->pts_creds->destroy(this->pts_creds);
	}
	DESTROY_IF(this->pts_db);
	DESTROY_IF(this->pts_credmgr);
	this->agent->destroy(this->agent);
	free(this);
	libpts_deinit();
}

/**
 * Described in header.
 */
imv_agent_if_t *imv_attestation_agent_create(const char *name, TNC_IMVID id,
										 TNC_Version *actual_version)
{
	private_imv_attestation_agent_t *this;
	char *hash_alg, *dh_group, *cadir;

	hash_alg = lib->settings->get_str(lib->settings,
					"libimcv.plugins.imv-attestation.hash_algorithm", "sha256");
	dh_group = lib->settings->get_str(lib->settings,
					"libimcv.plugins.imv-attestation.dh_group", "ecp256");
	cadir = lib->settings->get_str(lib->settings,
					"libimcv.plugins.imv-attestation.cadir", NULL);
	libpts_init();

	INIT(this,
		.public = {
			.bind_functions = _bind_functions,
			.notify_connection_change = _notify_connection_change,
			.receive_message = _receive_message,
			.receive_message_long = _receive_message_long,
			.batch_ending = _batch_ending,
			.solicit_recommendation = _solicit_recommendation,
			.destroy = _destroy,
		},
		.agent = imv_agent_create(name, msg_types, countof(msg_types), id,
								  actual_version),
		.supported_algorithms = PTS_MEAS_ALGO_NONE,
		.supported_dh_groups = PTS_DH_GROUP_NONE,
		.pts_credmgr = credential_manager_create(),
		.pts_creds = pts_creds_create(cadir),
		.pts_db = pts_database_create(imcv_db),
	);

	if (!this->agent ||
		!pts_meas_algo_update(hash_alg, &this->supported_algorithms) ||
		!pts_dh_group_update(dh_group, &this->supported_dh_groups))
	{
		destroy(this);
		return NULL;
	}

	if (this->pts_creds)
	{
		this->pts_credmgr->add_set(this->pts_credmgr,
								   this->pts_creds->get_set(this->pts_creds));
	}

	return &this->public;
}

