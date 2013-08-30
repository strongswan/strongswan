/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "imv_swid_agent.h"
#include "imv_swid_state.h"

#include "libpts.h"
#include "swid/swid_error.h"
#include "swid/swid_inventory.h"
#include "tcg/swid/tcg_swid_attr_req.h"
#include "tcg/swid/tcg_swid_attr_tag_inv.h"
#include "tcg/swid/tcg_swid_attr_tag_id_inv.h"

#include <imcv.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <imv/imv_agent.h>
#include <imv/imv_msg.h>

#include <tncif_names.h>
#include <tncif_pa_subtypes.h>

#include <pen/pen.h>
#include <utils/debug.h>
#include <bio/bio_reader.h>

typedef struct private_imv_swid_agent_t private_imv_swid_agent_t;

/* Subscribed PA-TNC message subtypes */
static pen_type_t msg_types[] = {
	{ PEN_TCG, PA_SUBTYPE_TCG_SWID }
};

/**
 * Private data of an imv_swid_agent_t object.
 */
struct private_imv_swid_agent_t {

	/**
	 * Public members of imv_swid_agent_t
	 */
	imv_agent_if_t public;

	/**
	 * IMV agent responsible for generic functions
	 */
	imv_agent_t *agent;

};

METHOD(imv_agent_if_t, bind_functions, TNC_Result,
	private_imv_swid_agent_t *this, TNC_TNCS_BindFunctionPointer bind_function)
{
	return this->agent->bind_functions(this->agent, bind_function);
}

METHOD(imv_agent_if_t, notify_connection_change, TNC_Result,
	private_imv_swid_agent_t *this, TNC_ConnectionID id,
	TNC_ConnectionState new_state)
{
	imv_state_t *state;

	switch (new_state)
	{
		case TNC_CONNECTION_STATE_CREATE:
			state = imv_swid_state_create(id);
			return this->agent->create_state(this->agent, state);
		case TNC_CONNECTION_STATE_DELETE:
			return this->agent->delete_state(this->agent, id);
		default:
			return this->agent->change_state(this->agent, id, new_state, NULL);
	}
}

/**
 * Process a received message
 */
static TNC_Result receive_msg(private_imv_swid_agent_t *this,
							  imv_state_t *state, imv_msg_t *in_msg)
{
	imv_msg_t *out_msg;
	imv_session_t *session;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	TNC_Result result;
	bool fatal_error = FALSE;

	/* parse received PA-TNC message and handle local and remote errors */
	result = in_msg->receive(in_msg, &fatal_error);
	if (result != TNC_RESULT_SUCCESS)
	{
		return result;
	}

	session = state->get_session(state);

	/* analyze PA-TNC attributes */
	enumerator = in_msg->create_attribute_enumerator(in_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		TNC_IMV_Evaluation_Result eval;
		TNC_IMV_Action_Recommendation rec;
		pen_type_t type;
		u_int32_t request_id, last_eid, eid_epoch;
		swid_inventory_t *inventory;
		int tag_count;
		char result_str[BUF_LEN], *tag_item;
		imv_workitem_t *workitem, *found = NULL;
		enumerator_t *et, *ew;
		
		type = attr->get_type(attr);

		if (type.vendor_id == PEN_IETF && type.type == IETF_ATTR_PA_TNC_ERROR)
		{
			ietf_attr_pa_tnc_error_t *error_attr;
			pen_type_t error_code;
			chunk_t msg_info, description;
			bio_reader_t *reader;
			u_int32_t request_id = 0, max_attr_size;
			bool success;

			error_attr = (ietf_attr_pa_tnc_error_t*)attr;
			error_code = error_attr->get_error_code(error_attr);

			if (error_code.vendor_id == PEN_TCG)
			{
				fatal_error = TRUE;
				msg_info = error_attr->get_msg_info(error_attr);
				reader = bio_reader_create(msg_info);
				success = reader->read_uint32(reader, &request_id);

				DBG1(DBG_IMV, "received TCG error '%N' for request %d",
					 swid_error_code_names, error_code.type, request_id);
				if (!success)
				{
					reader->destroy(reader);
					continue;
				}
				if (error_code.type == TCG_SWID_RESPONSE_TOO_LARGE)
				{
					if (!reader->read_uint32(reader, &max_attr_size))
					{
						reader->destroy(reader);
						continue;
					}
					DBG1(DBG_IMV, "  maximum PA-TNC attribute size is %u bytes",
						max_attr_size);
				}
				description = reader->peek(reader);
				if (description.len)
				{ 
					DBG1(DBG_IMV, "  description: %.*s", description.len,
														 description.ptr);
				}
				reader->destroy(reader);
			}
		}
		else if (type.vendor_id != PEN_TCG)
		{
			continue;
		}

		switch (type.type)
		{
			case TCG_SWID_TAG_ID_INVENTORY:
			{
				tcg_swid_attr_tag_id_inv_t *attr_cast;
				swid_tag_id_t *tag_id;
				chunk_t tag_creator, unique_sw_id;

				attr_cast = (tcg_swid_attr_tag_id_inv_t*)attr;
				request_id = attr_cast->get_request_id(attr_cast);
				last_eid = attr_cast->get_last_eid(attr_cast, &eid_epoch);
				inventory = attr_cast->get_inventory(attr_cast);
				tag_item = "tag ID";
				DBG2(DBG_IMV, "received SWID %s inventory for request %d "
							  "at eid %d of epoch 0x%08x", tag_item,
							   request_id, last_eid, eid_epoch);

				et = inventory->create_enumerator(inventory);
				while (et->enumerate(et, &tag_id))
				{
					tag_creator = tag_id->get_tag_creator(tag_id);
					unique_sw_id = tag_id->get_unique_sw_id(tag_id, NULL);
					DBG3(DBG_IMV, "  %.*s_%.*s.swidtag",
						 tag_creator.len, tag_creator.ptr,
						 unique_sw_id.len, unique_sw_id.ptr);
				}
				et->destroy(et);

				if (request_id == 0)
				{
					/* TODO handle subscribed messages */
					break;
				}
				break;
			 }
			case TCG_SWID_TAG_INVENTORY:
			{
				tcg_swid_attr_tag_inv_t *attr_cast;
				swid_tag_t *tag;
				chunk_t tag_encoding;

				attr_cast = (tcg_swid_attr_tag_inv_t*)attr;
				request_id = attr_cast->get_request_id(attr_cast);
				last_eid = attr_cast->get_last_eid(attr_cast, &eid_epoch);
				inventory = attr_cast->get_inventory(attr_cast);
				tag_item = "tag";
				DBG2(DBG_IMV, "received SWID %s inventory for request %d "
							  "at eid %d of epoch 0x%08x", tag_item,
							   request_id, last_eid, eid_epoch);

				et = inventory->create_enumerator(inventory);
				while (et->enumerate(et, &tag))
				{
					tag_encoding = tag->get_encoding(tag);
					DBG3(DBG_IMV, "%.*s", tag_encoding.len, tag_encoding.ptr);
				}
				et->destroy(et);

				if (request_id == 0)
				{
					/* TODO handle subscribed messages */
					break;
				}
				break;
			}
			default:
				continue;
		 }

		ew = session->create_workitem_enumerator(session);
		while (ew->enumerate(ew, &workitem))
		{
			if (workitem->get_id(workitem) == request_id)
			{
				found = workitem;
				break;
			}
		}
		if (!found)
		{
			DBG1(DBG_IMV, "no workitem found for SWID %s inventory "
						  "with request ID %d", tag_item, request_id);
			ew->destroy(ew);
			continue;
		}

		eval = TNC_IMV_EVALUATION_RESULT_COMPLIANT;
		tag_count = inventory->get_count(inventory);
		snprintf(result_str, BUF_LEN, "received inventory of %d SWID %s%s",
				 tag_count, tag_item, (tag_count == 1) ? "" : "s");
		session->remove_workitem(session, ew);
		ew->destroy(ew);
		rec = found->set_result(found, result_str, eval);
		state->update_recommendation(state, rec, eval);
		imcv_db->finalize_workitem(imcv_db, found);
		found->destroy(found);
	}
	enumerator->destroy(enumerator);

	if (fatal_error)
	{
		state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);
		out_msg = imv_msg_create_as_reply(in_msg);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}

	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_if_t, receive_message, TNC_Result,
	private_imv_swid_agent_t *this, TNC_ConnectionID id,
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
	private_imv_swid_agent_t *this, TNC_ConnectionID id,
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
	private_imv_swid_agent_t *this, TNC_ConnectionID id)
{
	imv_msg_t *out_msg;
	imv_state_t *state;
	imv_session_t *session;
	imv_workitem_t *workitem;
	imv_swid_state_t *swid_state;
	imv_swid_handshake_state_t handshake_state;
	pa_tnc_attr_t *attr;
	TNC_IMVID imv_id;
	TNC_Result result = TNC_RESULT_SUCCESS;
	bool no_workitems = TRUE;
	u_int32_t request_id;
	u_int8_t flags;
	enumerator_t *enumerator;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	swid_state = (imv_swid_state_t*)state;
	handshake_state = swid_state->get_handshake_state(swid_state);
	session = state->get_session(state);
	imv_id = this->agent->get_id(this->agent);

	if (handshake_state == IMV_SWID_STATE_END)
	{
		return TNC_RESULT_SUCCESS;
	}

	/* create an empty out message - we might need it */
	out_msg = imv_msg_create(this->agent, state, id, imv_id, TNC_IMCID_ANY,
							 msg_types[0]);

	if (!session)
	{
		DBG2(DBG_IMV, "no workitems available - no evaluation possible");
		state->set_recommendation(state,
							TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
							TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		swid_state->set_handshake_state(swid_state, IMV_SWID_STATE_END);

		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}

	if (handshake_state == IMV_SWID_STATE_INIT)
	{
		enumerator = session->create_workitem_enumerator(session);
		if (enumerator)
		{
			while (enumerator->enumerate(enumerator, &workitem))
			{
				if (workitem->get_imv_id(workitem) != TNC_IMVID_ANY ||
					workitem->get_type(workitem) != IMV_WORKITEM_SWID_TAGS)
				{
					continue;
				}
				
				flags = TCG_SWID_ATTR_REQ_FLAG_NONE;
				if (strchr(workitem->get_arg_str(workitem), 'R'))
				{
					flags |= TCG_SWID_ATTR_REQ_FLAG_R;
				}
				if (strchr(workitem->get_arg_str(workitem), 'S'))
				{
					flags |= TCG_SWID_ATTR_REQ_FLAG_S;
				}
				if (strchr(workitem->get_arg_str(workitem), 'C'))
				{
					flags |= TCG_SWID_ATTR_REQ_FLAG_C;
				}
				request_id = workitem->get_id(workitem);

				attr = tcg_swid_attr_req_create(flags, request_id, 0);
				out_msg->add_attribute(out_msg, attr);
				workitem->set_imv_id(workitem, imv_id);
				no_workitems = FALSE;
				DBG2(DBG_IMV, "IMV %d issues SWID request %d",
						 imv_id, request_id);
			}
			enumerator->destroy(enumerator);

			if (no_workitems)
			{
				DBG2(DBG_IMV, "IMV %d has no workitems - "
							  "no evaluation requested", imv_id);
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			}
			handshake_state = IMV_SWID_STATE_WORKITEMS;
			swid_state->set_handshake_state(swid_state, handshake_state);
		}
	}

	/* finalized all workitems ? */
	if (handshake_state == IMV_SWID_STATE_WORKITEMS &&
		session->get_workitem_count(session, imv_id) == 0)
	{
		result = out_msg->send_assessment(out_msg);
		out_msg->destroy(out_msg);
		swid_state->set_handshake_state(swid_state, IMV_SWID_STATE_END);

		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
		return this->agent->provide_recommendation(this->agent, state);
	}

	/* send non-empty PA-TNC message with excl flag not set */
	if (out_msg->get_attribute_count(out_msg))
	{
		result = out_msg->send(out_msg, FALSE);
	}
	out_msg->destroy(out_msg);

	return result;
}

METHOD(imv_agent_if_t, solicit_recommendation, TNC_Result,
	private_imv_swid_agent_t *this, TNC_ConnectionID id)
{
	imv_state_t *state;

	if (!this->agent->get_state(this->agent, id, &state))
	{
		return TNC_RESULT_FATAL;
	}
	return this->agent->provide_recommendation(this->agent, state);
}

METHOD(imv_agent_if_t, destroy, void,
	private_imv_swid_agent_t *this)
{
	this->agent->destroy(this->agent);
	free(this);
	libpts_deinit();
}

/**
 * Described in header.
 */
imv_agent_if_t *imv_swid_agent_create(const char *name, TNC_IMVID id,
										 TNC_Version *actual_version)
{
	private_imv_swid_agent_t *this;
	imv_agent_t *agent;

	agent = imv_agent_create(name, msg_types, countof(msg_types), id,
							 actual_version);
	if (!agent)
	{
		return NULL;
	}

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
		.agent = agent,
	);

	libpts_init();

	return &this->public;
}

