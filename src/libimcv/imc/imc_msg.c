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

#include "imc_msg.h"

#include "ietf/ietf_attr.h"
#include "ietf/ietf_attr_assess_result.h"
#include "ietf/ietf_attr_remediation_instr.h"

#include <tncif_names.h>

#include <pen/pen.h>
#include <collections/linked_list.h>
#include <utils/debug.h>

typedef struct private_imc_msg_t private_imc_msg_t;

/**
 * Private data of a imc_msg_t object.
 *
 */
struct private_imc_msg_t {

	/**
	 * Public imc_msg_t interface.
	 */
	imc_msg_t public;

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
	 * Assigned IMC agent
	 */
	imc_agent_t *agent;

	/**
	 * Assigned IMC state
	 */
	imc_state_t *state;
};

METHOD(imc_msg_t, get_src_id, TNC_UInt32,
	private_imc_msg_t *this)
{
	return this->src_id;
}

METHOD(imc_msg_t, get_dst_id, TNC_UInt32,
	private_imc_msg_t *this)
{
	return this->dst_id;
}

METHOD(imc_msg_t, get_msg_type, pen_type_t,
	private_imc_msg_t *this)
{
	return this->msg_type;
}

METHOD(imc_msg_t, send_, TNC_Result,
	private_imc_msg_t *this, bool excl)
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
					DBG1(DBG_IMC, "PA-TNC attribute too large to send, deleted");
					attr->destroy(attr);
				}
			}
			this->attr_list->remove_at(this->attr_list, enumerator);
		}
		enumerator->destroy(enumerator);

		/* build and send the PA-TNC message via the IF-IMC interface */
		if (!pa_tnc_msg->build(pa_tnc_msg))
		{
			pa_tnc_msg->destroy(pa_tnc_msg);
			return TNC_RESULT_FATAL;
		}
		msg = pa_tnc_msg->get_encoding(pa_tnc_msg);
		DBG3(DBG_IMC, "created PA-TNC message: %B", &msg);

		if (this->state->has_long(this->state) && this->agent->send_message_long)
		{
			excl = excl && this->state->has_excl(this->state) &&
						   this->dst_id != TNC_IMVID_ANY;
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

/**
 * Print a clearly visible assessment header to the log
 */
static void print_assessment_header(const char *name, TNC_UInt32 dst_id,
									TNC_UInt32 src_id, bool *first)
{
	if (*first)
	{
		if (src_id == TNC_IMCID_ANY)
		{
			DBG1(DBG_IMC, "***** assessment of IMC %u \"%s\" *****",
						   dst_id, name);
		}
		else
		{
			DBG1(DBG_IMC, "***** assessment of IMC %u \"%s\" from IMV %u *****",
						   dst_id, name, src_id);
		}
		*first = FALSE;
	}
}

/**
 * Print a clearly visible assessment trailer to the log
 */
static void print_assessment_trailer(bool first)
{
	if (!first)
	{
		DBG1(DBG_IMC, "***** end of assessment *****");
	}
}

METHOD(imc_msg_t, receive, TNC_Result,
	private_imc_msg_t *this, bool *fatal_error)
{
	TNC_UInt32 target_imc_id;
	enumerator_t *enumerator;
	pa_tnc_attr_t *attr;
	pen_type_t attr_type;
	chunk_t msg;
	bool first = TRUE;

	if (this->state->has_long(this->state))
	{
		if (this->dst_id != TNC_IMCID_ANY)
		{
			DBG2(DBG_IMC, "IMC %u \"%s\" received message for Connection ID %u "
						  "from IMV %u to IMC %u",
						   this->agent->get_id(this->agent),
						   this->agent->get_name(this->agent),
						   this->connection_id, this->src_id, this->dst_id);
		}
		else
		{
			DBG2(DBG_IMC, "IMC %u \"%s\" received message for Connection ID %u "
						  "from IMV %u", this->agent->get_id(this->agent),
						   this->agent->get_name(this->agent),
						   this->connection_id, this->src_id);
		}
	}
	else
	{
		DBG2(DBG_IMC, "IMC %u \"%s\" received message for Connection ID %u",
					   this->agent->get_id(this->agent),
					   this->agent->get_name(this->agent),
					   this->connection_id);
	}
	msg = this->pa_msg->get_encoding(this->pa_msg);
	DBG3(DBG_IMC, "%B", &msg);

	switch (this->pa_msg->process(this->pa_msg))
	{
		case SUCCESS:
			break;
		case VERIFY_ERROR:
		{
			imc_msg_t *error_msg;
			TNC_Result result;

			error_msg = imc_msg_create_as_reply(&this->public);

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

	/* determine target IMC ID */
	target_imc_id = (this->dst_id != TNC_IMCID_ANY) ?
					 this->dst_id : this->agent->get_id(this->agent);

	/* preprocess any received IETF standard error attributes */
	*fatal_error = this->pa_msg->process_ietf_std_errors(this->pa_msg);

	/* preprocess any received IETF assessment result attribute */
	enumerator = this->pa_msg->create_attribute_enumerator(this->pa_msg);
	while (enumerator->enumerate(enumerator, &attr))
	{
		attr_type = attr->get_type(attr);

		if (attr_type.vendor_id != PEN_IETF)
		{
			continue;
		}
		if (attr_type.type == IETF_ATTR_ASSESSMENT_RESULT)
		{
			ietf_attr_assess_result_t *attr_cast;
			TNC_IMV_Evaluation_Result result;

			attr_cast = (ietf_attr_assess_result_t*)attr;
			result =  attr_cast->get_result(attr_cast);
			this->state->set_result(this->state, target_imc_id, result);

			print_assessment_header(this->agent->get_name(this->agent),
									target_imc_id, this->src_id, &first);
			DBG1(DBG_IMC, "assessment result is '%N'",
				 TNC_IMV_Evaluation_Result_names, result);
		}
		else if (attr_type.type == IETF_ATTR_REMEDIATION_INSTRUCTIONS)
		{
			ietf_attr_remediation_instr_t *attr_cast;
			pen_type_t parameters_type;
			chunk_t parameters, string, lang_code;

			attr_cast = (ietf_attr_remediation_instr_t*)attr;
			parameters_type = attr_cast->get_parameters_type(attr_cast);
			parameters = attr_cast->get_parameters(attr_cast);

			print_assessment_header(this->agent->get_name(this->agent),
									target_imc_id, this->src_id, &first);
			if (parameters_type.vendor_id == PEN_IETF)
			{
				switch (parameters_type.type)
				{
					case IETF_REMEDIATION_PARAMETERS_URI:
						DBG1(DBG_IMC, "remediation uri: %.*s",
									   parameters.len, parameters.ptr);
						break;
					case IETF_REMEDIATION_PARAMETERS_STRING:
						string = attr_cast->get_string(attr_cast, &lang_code);
						DBG1(DBG_IMC, "remediation string: [%.*s]\n%.*s",
									   lang_code.len, lang_code.ptr,
									   string.len, string.ptr);
						break;
					default:
						DBG1(DBG_IMC, "remediation parameters: %B", &parameters);
				}
			}
			else
			{
				DBG1(DBG_IMC, "remediation parameters: %B", &parameters);
			}
		}
	}
	enumerator->destroy(enumerator);

	print_assessment_trailer(first);

	return TNC_RESULT_SUCCESS;
}

METHOD(imc_msg_t, add_attribute, void,
	private_imc_msg_t *this, pa_tnc_attr_t *attr)
{
	this->attr_list->insert_last(this->attr_list, attr);
}

METHOD(imc_msg_t, create_attribute_enumerator, enumerator_t*,
	private_imc_msg_t *this)
{
	return this->pa_msg->create_attribute_enumerator(this->pa_msg);
}

METHOD(imc_msg_t, get_encoding, chunk_t,
	private_imc_msg_t *this)
{
	if (this->pa_msg)
	{
		return this->pa_msg->get_encoding(this->pa_msg);
	}
	return chunk_empty;
}

METHOD(imc_msg_t, destroy, void,
	private_imc_msg_t *this)
{
	this->attr_list->destroy_offset(this->attr_list,
									offsetof(pa_tnc_attr_t, destroy));
	DESTROY_IF(this->pa_msg);
	free(this);
}

/**
 * See header
 */
imc_msg_t *imc_msg_create(imc_agent_t *agent, imc_state_t *state,
						  TNC_ConnectionID connection_id,
						  TNC_UInt32 src_id, TNC_UInt32 dst_id,
						  pen_type_t msg_type)
{
	private_imc_msg_t *this;

	INIT(this,
		.public = {
			.get_src_id = _get_src_id,
			.get_dst_id = _get_dst_id,
			.get_msg_type = _get_msg_type,
			.send = _send_,
			.receive = _receive,
			.add_attribute = _add_attribute,
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
imc_msg_t* imc_msg_create_as_reply(imc_msg_t *msg)
{
	private_imc_msg_t *in;
	TNC_UInt32 src_id;

	in = (private_imc_msg_t*)msg;
	src_id = (in->dst_id != TNC_IMCID_ANY) ?
			  in->dst_id : in->agent->get_id(in->agent);

	return imc_msg_create(in->agent, in->state, in->connection_id, src_id,
						  in->src_id, in->msg_type);
}

/**
 * See header
 */
imc_msg_t *imc_msg_create_from_data(imc_agent_t *agent, imc_state_t *state,
									TNC_ConnectionID connection_id,
									TNC_MessageType msg_type,
									chunk_t msg)
{
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = msg_type >> 8;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	return imc_msg_create_from_long_data(agent, state, connection_id,
								TNC_IMVID_ANY, agent->get_id(agent),
								msg_vid, msg_subtype, msg);
}

/**
 * See header
 */
imc_msg_t *imc_msg_create_from_long_data(imc_agent_t *agent, imc_state_t *state,
										 TNC_ConnectionID connection_id,
										 TNC_UInt32 src_id,
										 TNC_UInt32 dst_id,
										 TNC_VendorID msg_vid,
										 TNC_MessageSubtype msg_subtype,
										 chunk_t msg)
{
	private_imc_msg_t *this;

	this = (private_imc_msg_t*)imc_msg_create(agent, state,
										connection_id, src_id, dst_id,
										pen_type_create(msg_vid, msg_subtype));
	this->pa_msg = pa_tnc_msg_create_from_data(msg);

	return &this->public;
}
