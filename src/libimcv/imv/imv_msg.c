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

#include "imv_msg.h"

#include "ietf/ietf_attr.h"
#include "ietf/ietf_attr_assess_result.h"
#include "ietf/ietf_attr_remediation_instr.h"

#include <tncif_names.h>

#include <pen/pen.h>
#include <collections/linked_list.h>
#include <utils/debug.h>

typedef struct private_imv_msg_t private_imv_msg_t;

/**
 * Private data of a imv_msg_t object.
 *
 */
struct private_imv_msg_t {

	/**
	 * Public imv_msg_t interface.
	 */
	imv_msg_t public;

	/**
	 * Connection ID
	 */
	TNC_ConnectionID connection_id;

	/**
	 * source ID
	 */
	TNC_UInt32 src_id;

	/**
	 * destination ID
	 */
	TNC_UInt32 dst_id;

	/**
	 * PA-TNC message type
	 */
	pen_type_t msg_type;

	/**
	 * List of PA-TNC attributes to be sent
	 */
	linked_list_t *attr_list;

	/**
	 * PA-TNC message
	 */
	pa_tnc_msg_t *pa_msg;

	/**
	 * Assigned IMV agent
	 */
	imv_agent_t *agent;

	/**
	 * Assigned IMV state
	 */
	imv_state_t *state;
};

METHOD(imv_msg_t, get_src_id, TNC_UInt32,
	private_imv_msg_t *this)
{
	return this->src_id;
}

METHOD(imv_msg_t, get_dst_id, TNC_UInt32,
	private_imv_msg_t *this)
{
	return this->dst_id;
}

METHOD(imv_msg_t, set_msg_type, void,
	private_imv_msg_t *this, pen_type_t msg_type)
{
	if (msg_type.vendor_id != this->msg_type.vendor_id ||
		msg_type.type != this->msg_type.type)
	{
		this->msg_type = msg_type;
		this->dst_id = TNC_IMCID_ANY;
	}
}

METHOD(imv_msg_t, get_msg_type, pen_type_t,
	private_imv_msg_t *this)
{
	return this->msg_type;
}

METHOD(imv_msg_t, add_attribute, void,
	private_imv_msg_t *this, pa_tnc_attr_t *attr)
{
	this->attr_list->insert_last(this->attr_list, attr);
}

METHOD(imv_msg_t, send_, TNC_Result,
	private_imv_msg_t *this, bool excl)
{
	pa_tnc_msg_t *pa_tnc_msg;
	pa_tnc_attr_t *attr;
	TNC_UInt32 msg_flags;
	TNC_MessageType msg_type;
	bool attr_added;
	chunk_t msg;
	enumerator_t *enumerator;
	TNC_Result result = TNC_RESULT_SUCCESS;

	while (this->attr_list->get_count(this->attr_list))
	{
		pa_tnc_msg = pa_tnc_msg_create(this->state->get_max_msg_len(this->state));
		attr_added = FALSE;

		enumerator = this->attr_list->create_enumerator(this->attr_list);
		while (enumerator->enumerate(enumerator, &attr))
		{
			if (pa_tnc_msg->add_attribute(pa_tnc_msg, attr))
			{
				attr_added = TRUE;
			}
			else
			{
				if (attr_added)
				{
					break;
				}
				else
				{
					DBG1(DBG_IMV, "PA-TNC attribute too large to send, deleted");
					attr->destroy(attr);
				}
			}
			this->attr_list->remove_at(this->attr_list, enumerator);
		}
		enumerator->destroy(enumerator);

		/* build and send the PA-TNC message via the IF-IMV interface */
		if (!pa_tnc_msg->build(pa_tnc_msg))
		{
			pa_tnc_msg->destroy(pa_tnc_msg);
			return TNC_RESULT_FATAL;
		}
		msg = pa_tnc_msg->get_encoding(pa_tnc_msg);
		DBG3(DBG_IMV, "created PA-TNC message: %B", &msg);

		if (this->state->has_long(this->state) && this->agent->send_message_long)
		{
			excl = excl && this->state->has_excl(this->state) &&
						   this->dst_id != TNC_IMCID_ANY;
			msg_flags = excl ? TNC_MESSAGE_FLAGS_EXCLUSIVE : 0;
			result = this->agent->send_message_long(this->src_id,
							this->connection_id, msg_flags,	msg.ptr, msg.len,
							this->msg_type.vendor_id, this->msg_type.type,
							this->dst_id);
		}
		else if (this->agent->send_message)
		{
			msg_type = (this->msg_type.vendor_id << 8) |
					   (this->msg_type.type & 0x000000ff);
			result = this->agent->send_message(this->src_id, this->connection_id,
											   msg.ptr, msg.len, msg_type);
		}

		pa_tnc_msg->destroy(pa_tnc_msg);

		if (result != TNC_RESULT_SUCCESS)
		{
			break;
		}
	}
	return result;
}

METHOD(imv_msg_t, send_assessment, TNC_Result,
	private_imv_msg_t *this)
{
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	pa_tnc_attr_t *attr;
	chunk_t string = chunk_empty;
	char *lang_code = NULL, *uri = NULL;
	enumerator_t *e;

	/* Remove any attributes that have already been constructed */
	while (this->attr_list->remove_last(this->attr_list, (void**)&attr) == SUCCESS)
	{
		attr->destroy(attr);
	}

	/* Send an IETF Assessment Result attribute if enabled */
	if (lib->settings->get_bool(lib->settings, "%s.imcv.assessment_result",
								TRUE, lib->ns))
	{
		this->state->get_recommendation(this->state, &rec, &eval);
		attr = ietf_attr_assess_result_create(eval);
		add_attribute(this, attr);

		/* Send IETF Remediation Instructions if available */
		if (eval != TNC_IMV_EVALUATION_RESULT_COMPLIANT)
		{
			e = this->agent->create_language_enumerator(this->agent,
									this->state);
			if (this->state->get_remediation_instructions(this->state,
									e, &string, &lang_code, &uri))
			{
				if (string.len && lang_code)
				{
					attr = ietf_attr_remediation_instr_create_from_string(string,
									chunk_create(lang_code, strlen(lang_code)));
					add_attribute(this, attr);
				}
				if (uri)
				{
					attr = ietf_attr_remediation_instr_create_from_uri(
									chunk_create(uri, strlen(uri)));
					add_attribute(this, attr);
				}
			}
			e->destroy(e);
		}

		/* send PA-TNC message with the excl flag set */
		return send_(this, TRUE);
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_msg_t, receive, TNC_Result,
	private_imv_msg_t *this, bool *fatal_error)
{
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	chunk_t msg;

	if (this->state->has_long(this->state))
	{
		if (this->dst_id != TNC_IMVID_ANY)
		{
			DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u "
						  "from IMC %u to IMV %u",
						   this->agent->get_id(this->agent),
						   this->agent->get_name(this->agent),
						   this->connection_id, this->src_id, this->dst_id);
		}
		else
		{
			DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u "
						  "from IMC %u", this->agent->get_id(this->agent),
						   this->agent->get_name(this->agent),
						   this->connection_id, this->src_id);
		}
	}
	else
	{
		DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u",
					   this->agent->get_id(this->agent),
					   this->agent->get_name(this->agent),
					   this->connection_id);
	}
	msg = this->pa_msg->get_encoding(this->pa_msg);
	DBG3(DBG_IMV, "%B", &msg);

	switch (this->pa_msg->process(this->pa_msg))
	{
		case SUCCESS:
			break;
		case VERIFY_ERROR:
		{
			imv_msg_t *error_msg;
			TNC_Result result;

			error_msg = imv_msg_create_as_reply(&this->public);

			/* extract and copy by reference all error attributes */
			enumerator = this->pa_msg->create_error_enumerator(this->pa_msg);
			while (enumerator->enumerate(enumerator, &attr))
			{
				error_msg->add_attribute(error_msg, attr->get_ref(attr));
			}
			enumerator->destroy(enumerator);

			/*
			 * send the PA-TNC message containing all error attributes
			 * with the excl flag set
			 */
			result = error_msg->send(error_msg, TRUE);
			error_msg->destroy(error_msg);
			return result;
		}
		case FAILED:
		default:
			return TNC_RESULT_FATAL;
	}

	/* preprocess any received IETF standard error attributes */
	*fatal_error = this->pa_msg->process_ietf_std_errors(this->pa_msg);

	return TNC_RESULT_SUCCESS;
}

METHOD(imv_msg_t, get_attribute_count, int,
	private_imv_msg_t *this)
{
	return this->attr_list->get_count(this->attr_list);
}

METHOD(imv_msg_t, create_attribute_enumerator, enumerator_t*,
	private_imv_msg_t *this)
{
	return this->pa_msg->create_attribute_enumerator(this->pa_msg);
}

METHOD(imv_msg_t, get_encoding, chunk_t,
	private_imv_msg_t *this)
{
	if (this->pa_msg)
	{
		return this->pa_msg->get_encoding(this->pa_msg);
	}
	return chunk_empty;
}

METHOD(imv_msg_t, destroy, void,
	private_imv_msg_t *this)
{
	this->attr_list->destroy_offset(this->attr_list,
									offsetof(pa_tnc_attr_t, destroy));
	DESTROY_IF(this->pa_msg);
	free(this);
}

/**
 * See header
 */
imv_msg_t *imv_msg_create(imv_agent_t *agent, imv_state_t *state,
						  TNC_ConnectionID connection_id,
						  TNC_UInt32 src_id, TNC_UInt32 dst_id,
						  pen_type_t msg_type)
{
	private_imv_msg_t *this;

	INIT(this,
		.public = {
			.get_src_id = _get_src_id,
			.get_dst_id = _get_dst_id,
			.set_msg_type = _set_msg_type,
			.get_msg_type = _get_msg_type,
			.send = _send_,
			.send_assessment = _send_assessment,
			.receive = _receive,
			.add_attribute = _add_attribute,
			.get_attribute_count = _get_attribute_count,
			.create_attribute_enumerator = _create_attribute_enumerator,
			.get_encoding = _get_encoding,
			.destroy = _destroy,
		},
		.connection_id = connection_id,
		.src_id = src_id,
		.dst_id = dst_id,
		.msg_type = msg_type,
		.attr_list = linked_list_create(),
		.agent = agent,
		.state = state,
	);

	return &this->public;
}

/**
 * See header
 */
imv_msg_t* imv_msg_create_as_reply(imv_msg_t *msg)
{
	private_imv_msg_t *in;
	TNC_UInt32 src_id;

	in = (private_imv_msg_t*)msg;
	src_id = (in->dst_id != TNC_IMVID_ANY) ?
			  in->dst_id : in->agent->get_id(in->agent);

	return imv_msg_create(in->agent, in->state, in->connection_id, src_id,
						  in->src_id, in->msg_type);
}

/**
 * See header
 */
imv_msg_t *imv_msg_create_from_data(imv_agent_t *agent, imv_state_t *state,
									TNC_ConnectionID connection_id,
									TNC_MessageType msg_type,
									chunk_t msg)
{
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = msg_type >> 8;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	return imv_msg_create_from_long_data(agent, state, connection_id,
								TNC_IMCID_ANY, agent->get_id(agent),
								msg_vid, msg_subtype, msg);
}

/**
 * See header
 */
imv_msg_t *imv_msg_create_from_long_data(imv_agent_t *agent, imv_state_t *state,
										 TNC_ConnectionID connection_id,
										 TNC_UInt32 src_id,
										 TNC_UInt32 dst_id,
										 TNC_VendorID msg_vid,
										 TNC_MessageSubtype msg_subtype,
										 chunk_t msg)
{
	private_imv_msg_t *this;

	this = (private_imv_msg_t*)imv_msg_create(agent, state,
										connection_id, src_id, dst_id,
										pen_type_create(msg_vid, msg_subtype));
	this->pa_msg = pa_tnc_msg_create_from_data(msg);

	return &this->public;
}
