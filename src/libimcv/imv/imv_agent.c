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

#include "imcv.h"
#include "imv_agent.h"
#include "ietf/ietf_attr_assess_result.h"

#include <tncif_names.h>

#include <debug.h>
#include <threading/rwlock.h>

typedef struct private_imv_agent_t private_imv_agent_t;

/**
 * Private data of an imv_agent_t object.
 */
struct private_imv_agent_t {

	/**
	 * Public members of imv_agent_t
	 */
	imv_agent_t public;

	/**
	 * name of IMV
	 */
	const char *name;

	/**
	 * message vendor ID of IMV
	 */
	TNC_VendorID vendor_id;

	/**
	 * message subtype of IMV
	 */
	TNC_MessageSubtype subtype;

	/**
	 * Maximum PA-TNC Message size
	 */
	size_t max_msg_len;

	/**
	 * ID of IMV as assigned by TNCS
	 */
	TNC_IMVID id;

	/**
	 * List of additional IMV IDs assigned by TNCS
	 */
	linked_list_t *additional_ids;

	/**
	 * list of TNCS connection entries
	 */
	linked_list_t *connections;

	/**
	 * rwlock to lock TNCS connection entries
	 */
	rwlock_t *connection_lock;

	/**
	 * Inform a TNCS about the set of message types the IMV is able to receive
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param supported_types	list of supported message types
	 * @param type_count		number of list elements
	 * @return					TNC result code
	 */
	TNC_Result (*report_message_types)(TNC_IMVID imv_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count);

	/**
	 * Inform a TNCS about the set of message types the IMV is able to receive
	 *
	 * @param imv_id				IMV ID assigned by TNCS
	 * @param supported_vids		list of supported message vendor IDs
	 * @param supported_subtypes	list of supported message subtypes
	 * @param type_count			number of list elements
	 * @return						TNC result code
	 */
	TNC_Result (*report_message_types_long)(TNC_IMVID imv_id,
									TNC_VendorIDList supported_vids,
									TNC_MessageSubtypeList supported_subtypes,
									TNC_UInt32 type_count);

	/**
	 * Call when an IMV-IMC message is to be sent
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param msg				message to send
	 * @param msg_len			message length in bytes
	 * @param msg_type			message type
	 * @return					TNC result code
	 */
	TNC_Result (*send_message)(TNC_IMVID imv_id,
							   TNC_ConnectionID connection_id,
							   TNC_BufferReference msg,
							   TNC_UInt32 msg_len,
							   TNC_MessageType msg_type);

	/**
	 * Call when an IMV-IMC message is to be sent with long message types
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param msg_flags			message flags
	 * @param msg				message to send
	 * @param msg_len			message length in bytes
	 * @param msg_vid			message vendor ID
	 * @param msg_subtype		message subtype
	 * @param dst_imc_id		destination IMC ID
	 * @return					TNC result code
	 */
	TNC_Result (*send_message_long)(TNC_IMVID imv_id,
									TNC_ConnectionID connection_id,
									TNC_UInt32 msg_flags,
									TNC_BufferReference msg,
									TNC_UInt32 msg_len,
									TNC_VendorID msg_vid,
									TNC_MessageSubtype msg_subtype,
									TNC_UInt32 dst_imc_id);

	/**
	 * Deliver IMV Action Recommendation and IMV Evaluation Results to the TNCS
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 # @param connection_id		network connection ID assigned by TNCS
	 * @param rec				IMV action recommendation
	 * @param eval				IMV evaluation result
	 * @return					TNC result code
	 */
	TNC_Result (*provide_recommendation)(TNC_IMVID imv_id,
										 TNC_ConnectionID connection_id,
										 TNC_IMV_Action_Recommendation rec,
										 TNC_IMV_Evaluation_Result eval);

	/**
	 * Get the value of an attribute associated with a connection
	 * or with the TNCS as a whole.
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param attribute_id		attribute ID
	 * @param buffer_len		length of buffer in bytes
	 * @param buffer			buffer
	 * @param out_value_len		size in bytes of attribute stored in buffer
	 * @return					TNC result code
	 */
	TNC_Result (*get_attribute)(TNC_IMVID imv_id,
								TNC_ConnectionID connection_id,
								TNC_AttributeID attribute_id,
								TNC_UInt32 buffer_len,
								TNC_BufferReference buffer,
								TNC_UInt32 *out_value_len);

	/**
	 * Set the value of an attribute associated with a connection
	 * or with the TNCS as a whole.
	 *
	 * @param imv_id			IMV ID assigned by TNCS
	 * @param connection_id		network connection ID assigned by TNCS
	 * @param attribute_id		attribute ID
	 * @param buffer_len		length of buffer in bytes
	 * @param buffer			buffer
	 * @return					TNC result code
	 */
	TNC_Result (*set_attribute)(TNC_IMVID imv_id,
								TNC_ConnectionID connection_id,
								TNC_AttributeID attribute_id,
								TNC_UInt32 buffer_len,
								TNC_BufferReference buffer);

	/**
	 * Reserve an additional IMV ID
	 *
	 * @param imv_id			primary IMV ID assigned by TNCS
	 * @param out_imv_id		additional IMV ID assigned by TNCS
	 * @return					TNC result code
	 */
	TNC_Result (*reserve_additional_id)(TNC_IMVID imv_id,
										TNC_UInt32 *out_imv_id);

};

METHOD(imv_agent_t, bind_functions, TNC_Result,
	private_imv_agent_t *this, TNC_TNCS_BindFunctionPointer bind_function)
{
	if (!bind_function)
	{
		DBG1(DBG_IMV, "TNC server failed to provide bind function");
		return TNC_RESULT_INVALID_PARAMETER;
	}
	if (bind_function(this->id, "TNC_TNCS_ReportMessageTypes",
			(void**)&this->report_message_types) != TNC_RESULT_SUCCESS)
	{
		this->report_message_types = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_ReportMessageTypesLong",
			(void**)&this->report_message_types_long) != TNC_RESULT_SUCCESS)
	{
		this->report_message_types_long = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_RequestHandshakeRetry",
			(void**)&this->public.request_handshake_retry) != TNC_RESULT_SUCCESS)
	{
		this->public.request_handshake_retry = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_SendMessage",
			(void**)&this->send_message) != TNC_RESULT_SUCCESS)
	{
		this->send_message = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_SendMessageLong",
			(void**)&this->send_message_long) != TNC_RESULT_SUCCESS)
	{
		this->send_message_long = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_ProvideRecommendation",
			(void**)&this->provide_recommendation) != TNC_RESULT_SUCCESS)
	{
		this->provide_recommendation = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_GetAttribute",
			(void**)&this->get_attribute) != TNC_RESULT_SUCCESS)
	{
		this->get_attribute = NULL;
	}
	if (bind_function(this->id, "TNC_TNCS_SetAttribute",
			(void**)&this->set_attribute) != TNC_RESULT_SUCCESS)
	{
		this->set_attribute = NULL;
	}
	if (bind_function(this->id, "TNC_TNCC_ReserveAdditionalIMVID",
			(void**)&this->reserve_additional_id) != TNC_RESULT_SUCCESS)
	{
		this->reserve_additional_id = NULL;
	}
	DBG2(DBG_IMV, "IMV %u \"%s\" provided with bind function",
				  this->id, this->name);

	if (this->report_message_types_long)
	{
		this->report_message_types_long(this->id, &this->vendor_id,
										&this->subtype, 1);
	}
	else if (this->report_message_types &&
			 this->vendor_id <= TNC_VENDORID_ANY &&
			 this->subtype <= TNC_SUBTYPE_ANY)
	{
		TNC_MessageType type;

		type = (this->vendor_id << 8) | this->subtype;
		this->report_message_types(this->id, &type, 1);
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * finds a connection state based on its Connection ID
 */
static imv_state_t* find_connection(private_imv_agent_t *this,
									 TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	imv_state_t *state, *found = NULL;

	this->connection_lock->read_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &state))
	{
		if (id == state->get_connection_id(state))
		{
			found = state;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	return found;
}

/**
 * delete a connection state with a given Connection ID
 */
static bool delete_connection(private_imv_agent_t *this, TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	imv_state_t *state;
	bool found = FALSE;

	this->connection_lock->write_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &state))
	{
		if (id == state->get_connection_id(state))
		{
			found = TRUE;
			state->destroy(state);
			this->connections->remove_at(this->connections, enumerator);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	return found;
}

/**
 * Read a boolean attribute
 */
static bool get_bool_attribute(private_imv_agent_t *this, TNC_ConnectionID id,
							   TNC_AttributeID attribute_id)
{
	TNC_UInt32 len;
	char buf[4];

	return this->get_attribute  &&
		   this->get_attribute(this->id, id, attribute_id, 4, buf, &len) ==
							   TNC_RESULT_SUCCESS && len == 1 && *buf == 0x01;
 }

/**
 * Read a string attribute
 */
static char* get_str_attribute(private_imv_agent_t *this, TNC_ConnectionID id,
								TNC_AttributeID attribute_id)
{
	TNC_UInt32 len;
	char buf[BUF_LEN];

	if (this->get_attribute  &&
		this->get_attribute(this->id, id, attribute_id, BUF_LEN, buf, &len) ==
							TNC_RESULT_SUCCESS && len <= BUF_LEN)
	{
		return strdup(buf);
	}
	return NULL;
 }

/**
 * Read an UInt32 attribute
 */
static u_int32_t get_uint_attribute(private_imv_agent_t *this, TNC_ConnectionID id,
									TNC_AttributeID attribute_id)
{
	TNC_UInt32 len;
	char buf[4];

	if (this->get_attribute  &&
		this->get_attribute(this->id, id, attribute_id, 4, buf, &len) ==
							TNC_RESULT_SUCCESS && len == 4)
	{
		return untoh32(buf);
	}
	return 0;
 }

METHOD(imv_agent_t, create_state, TNC_Result,
	private_imv_agent_t *this, imv_state_t *state)
{
	TNC_ConnectionID conn_id;
	char *tnccs_p = NULL, *tnccs_v = NULL, *t_p = NULL, *t_v = NULL;
	bool has_long = FALSE, has_excl = FALSE, has_soh = FALSE;
	u_int32_t max_msg_len;

	conn_id = state->get_connection_id(state);
	if (find_connection(this, conn_id))
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" already created a state for Connection ID %u",
					   this->id, this->name, conn_id);
		state->destroy(state);
		return TNC_RESULT_OTHER;
	}

	/* Get and display attributes from TNCS via IF-IMV */
	has_long = get_bool_attribute(this, conn_id, TNC_ATTRIBUTEID_HAS_LONG_TYPES);
	has_excl = get_bool_attribute(this, conn_id, TNC_ATTRIBUTEID_HAS_EXCLUSIVE);
	has_soh  = get_bool_attribute(this, conn_id, TNC_ATTRIBUTEID_HAS_SOH);
	tnccs_p = get_str_attribute(this, conn_id, TNC_ATTRIBUTEID_IFTNCCS_PROTOCOL);
	tnccs_v = get_str_attribute(this, conn_id, TNC_ATTRIBUTEID_IFTNCCS_VERSION);
	t_p = get_str_attribute(this, conn_id, TNC_ATTRIBUTEID_IFT_PROTOCOL);
	t_v = get_str_attribute(this, conn_id, TNC_ATTRIBUTEID_IFT_VERSION);
	max_msg_len = get_uint_attribute(this, conn_id, TNC_ATTRIBUTEID_MAX_MESSAGE_SIZE);

	state->set_flags(state, has_long, has_excl);
	state->set_max_msg_len(state, max_msg_len);

	DBG2(DBG_IMV, "IMV %u \"%s\" created a state for %s %s Connection ID %u: "
				  "%slong %sexcl %ssoh", this->id, this->name,
				  tnccs_p ? tnccs_p:"?", tnccs_v ? tnccs_v:"?", conn_id,
			      has_long ? "+":"-", has_excl ? "+":"-", has_soh ? "+":"-");
	DBG2(DBG_IMV, "  over %s %s with maximum PA-TNC message size of %u bytes",
				  t_p ? t_p:"?", t_v ? t_v :"?", max_msg_len);

	free(tnccs_p);
	free(tnccs_v);
	free(t_p);
	free(t_v);

	this->connection_lock->write_lock(this->connection_lock);
	this->connections->insert_last(this->connections, state);
	this->connection_lock->unlock(this->connection_lock);
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_t, delete_state, TNC_Result,
	private_imv_agent_t *this, TNC_ConnectionID connection_id)
{
	if (!delete_connection(this, connection_id))
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return TNC_RESULT_FATAL;
	}
	DBG2(DBG_IMV, "IMV %u \"%s\" deleted the state of Connection ID %u",
				  this->id, this->name, connection_id);
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_t, change_state, TNC_Result,
	private_imv_agent_t *this, TNC_ConnectionID connection_id,
							   TNC_ConnectionState new_state,
							   imv_state_t **state_p)
{
	imv_state_t *state;

	switch (new_state)
	{
		case TNC_CONNECTION_STATE_HANDSHAKE:
		case TNC_CONNECTION_STATE_ACCESS_ALLOWED:
		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
			state = find_connection(this, connection_id);
			if (!state)
			{
				DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
							  this->id, this->name, connection_id);
				return TNC_RESULT_FATAL;
			}
			state->change_state(state, new_state);
			DBG2(DBG_IMV, "IMV %u \"%s\" changed state of Connection ID %u to '%N'",
						  this->id, this->name, connection_id,
						  TNC_Connection_State_names, new_state);
			if (state_p)
			{
				*state_p = state;
			}
			break;
		case TNC_CONNECTION_STATE_CREATE:
			DBG1(DBG_IMV, "state '%N' should be handled by create_state()",
						  TNC_Connection_State_names, new_state);
				return TNC_RESULT_FATAL;
		case TNC_CONNECTION_STATE_DELETE:
			DBG1(DBG_IMV, "state '%N' should be handled by delete_state()",
						  TNC_Connection_State_names, new_state);
				return TNC_RESULT_FATAL;
		default:
			DBG1(DBG_IMV, "IMV %u \"%s\" was notified of unknown state %u "
				 		  "for Connection ID %u",
						  this->id, this->name, new_state, connection_id);
			return TNC_RESULT_INVALID_PARAMETER;
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_t, get_state, bool,
	private_imv_agent_t *this, TNC_ConnectionID connection_id,
							   imv_state_t **state)
{
	*state = find_connection(this, connection_id);
	if (!*state)
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return FALSE;
	}
	return TRUE;
}

METHOD(imv_agent_t, send_message, TNC_Result,
	private_imv_agent_t *this, TNC_ConnectionID connection_id, bool excl,
	TNC_UInt32 src_imv_id, TNC_UInt32 dst_imc_id, linked_list_t *attr_list)
{
	TNC_MessageType type;
	TNC_UInt32 msg_flags;
	TNC_Result result = TNC_RESULT_FATAL;
	imv_state_t *state;
	pa_tnc_attr_t *attr;
	pa_tnc_msg_t *pa_tnc_msg;
	chunk_t msg;
	enumerator_t *enumerator;
	bool attr_added;

	state = find_connection(this, connection_id);
	if (!state)
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return TNC_RESULT_FATAL;
	}

	while (attr_list->get_count(attr_list))
	{
		pa_tnc_msg = pa_tnc_msg_create(this->max_msg_len);
		attr_added = FALSE;

		enumerator = attr_list->create_enumerator(attr_list);
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
			attr_list->remove_at(attr_list, enumerator);
		}
		enumerator->destroy(enumerator);

		/* build and send the PA-TNC message via the IF-IMV interface */
		if (!pa_tnc_msg->build(pa_tnc_msg))
		{
			pa_tnc_msg->destroy(pa_tnc_msg);
			return TNC_RESULT_FATAL;
		}
		msg = pa_tnc_msg->get_encoding(pa_tnc_msg);

		if (state->has_long(state) && this->send_message_long)
		{
			if (!src_imv_id)
			{
				src_imv_id = this->id;
			}
			msg_flags = excl ? TNC_MESSAGE_FLAGS_EXCLUSIVE : 0;

			result = this->send_message_long(src_imv_id, connection_id,
								msg_flags, msg.ptr, msg.len, this->vendor_id,
								this->subtype, dst_imc_id);
		}
		else if (this->send_message)
		{
			type = (this->vendor_id << 8) | this->subtype;

			result = this->send_message(this->id, connection_id, msg.ptr,
								msg.len, type);
		}

		pa_tnc_msg->destroy(pa_tnc_msg);

		if (result != TNC_RESULT_SUCCESS)
		{
			break;
		}
	}
	return result;
}

METHOD(imv_agent_t, set_recommendation, TNC_Result,
	private_imv_agent_t *this, TNC_ConnectionID connection_id,
							   TNC_IMV_Action_Recommendation rec,
							   TNC_IMV_Evaluation_Result eval)
{
	imv_state_t *state;

	state = find_connection(this, connection_id);
	if (!state)
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return TNC_RESULT_FATAL;
	}

	state->set_recommendation(state, rec, eval);
	return this->provide_recommendation(this->id, connection_id, rec, eval);
}

METHOD(imv_agent_t, receive_message, TNC_Result,
	private_imv_agent_t *this, imv_state_t *state, chunk_t msg,
	TNC_VendorID msg_vid, TNC_MessageSubtype msg_subtype,
	TNC_UInt32 src_imc_id, TNC_UInt32 dst_imv_id, pa_tnc_msg_t **pa_tnc_msg)
{
	pa_tnc_msg_t *pa_msg;
	pa_tnc_attr_t *error_attr;
	linked_list_t *error_attr_list;
	enumerator_t *enumerator;
	TNC_UInt32 src_imv_id, dst_imc_id;
	TNC_ConnectionID connection_id;
	TNC_Result result;

	connection_id = state->get_connection_id(state);

	if (state->has_long(state))
	{
		if (dst_imv_id != TNC_IMVID_ANY)
		{
			DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u "
						  "from IMC %u to IMV %u", this->id, this->name,
						   connection_id, src_imc_id, dst_imv_id);
		}
		else
		{
			DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u "
						  "from IMC %u", this->id, this->name, connection_id,
						   src_imc_id);
		}
	}
	else
	{
		DBG2(DBG_IMV, "IMV %u \"%s\" received message for Connection ID %u",
					   this->id, this->name, connection_id);
	}

	*pa_tnc_msg = NULL;
	pa_msg = pa_tnc_msg_create_from_data(msg);

	switch (pa_msg->process(pa_msg))
	{
		case SUCCESS:
			*pa_tnc_msg = pa_msg;
			break;
		case VERIFY_ERROR:
			/* extract and copy by refence all error attributes */
			error_attr_list = linked_list_create();

			enumerator = pa_msg->create_error_enumerator(pa_msg);
			while (enumerator->enumerate(enumerator, &error_attr))
			{
				error_attr_list->insert_last(error_attr_list,
											 error_attr->get_ref(error_attr));
			}
			enumerator->destroy(enumerator);

			src_imv_id = (dst_imv_id == TNC_IMVID_ANY) ? this->id : dst_imv_id;
			dst_imc_id = state->has_excl(state) ? src_imc_id : TNC_IMCID_ANY;

			result = send_message(this, connection_id, state->has_excl(state),
 								  src_imv_id, dst_imc_id, error_attr_list);

			error_attr_list->destroy(error_attr_list);
			pa_msg->destroy(pa_msg);
			return result;
		case FAILED:
		default:
			pa_msg->destroy(pa_msg);
			state->set_recommendation(state,
							TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
							TNC_IMV_EVALUATION_RESULT_ERROR);
			return this->provide_recommendation(this->id, connection_id,
							TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
							TNC_IMV_EVALUATION_RESULT_ERROR);
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_t, provide_recommendation, TNC_Result,
	private_imv_agent_t *this, TNC_ConnectionID connection_id,
	TNC_UInt32 dst_imc_id)
{
	imv_state_t *state;
	linked_list_t *attr_list;
	pa_tnc_attr_t *attr;
	TNC_Result result;
	TNC_IMV_Action_Recommendation rec;
	TNC_IMV_Evaluation_Result eval;
	TNC_UInt32 lang_len;
	char buf[BUF_LEN];
	chunk_t pref_lang = { buf, 0 }, reason_string, reason_lang;

	state = find_connection(this, connection_id);
	if (!state)
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return TNC_RESULT_FATAL;
	}
	state->get_recommendation(state, &rec, &eval);

	/* send a reason string if action recommendation is not allow */
	if (rec != TNC_IMV_ACTION_RECOMMENDATION_ALLOW)
	{
		/* check if there a preferred language has been requested */
		if (this->get_attribute  &&
			this->get_attribute(this->id, connection_id,
								TNC_ATTRIBUTEID_PREFERRED_LANGUAGE, BUF_LEN,
								buf, &lang_len) == TNC_RESULT_SUCCESS &&
			lang_len <= BUF_LEN)
		{
			pref_lang.len = lang_len;
			DBG2(DBG_IMV, "preferred language is '%.*s'", (int)pref_lang.len,
				 pref_lang.ptr);
		}

		/* find a reason string for the preferred or default language and set it */
		if (this->set_attribute &&
			state->get_reason_string(state, pref_lang, &reason_string,
													   &reason_lang))
		{
			this->set_attribute(this->id, connection_id,
								TNC_ATTRIBUTEID_REASON_STRING,
								reason_string.len, reason_string.ptr);
			this->set_attribute(this->id, connection_id,
								TNC_ATTRIBUTEID_REASON_LANGUAGE,
								reason_lang.len, reason_lang.ptr);
		}
	}

	/* Send an IETF Assessment Result attribute if enabled */
	if (lib->settings->get_bool(lib->settings, "libimcv.assessment_result", TRUE))
	{
		attr = ietf_attr_assess_result_create(eval);
		attr_list = linked_list_create();
		attr_list->insert_last(attr_list, attr);
		result = send_message(this, connection_id, FALSE, this->id, dst_imc_id,
							  attr_list);
		attr_list->destroy(attr_list);
		if (result != TNC_RESULT_SUCCESS)
		{
			return result;
		}
	}
	return this->provide_recommendation(this->id, connection_id, rec, eval);
}

METHOD(imv_agent_t, reserve_additional_ids, TNC_Result,
	private_imv_agent_t *this, int count)
{
	TNC_Result result;
	TNC_UInt32 id;
	void *pointer;

	if (!this->reserve_additional_id)
	{
		DBG1(DBG_IMV, "IMV %u \"%s\" did not detect the capability to reserve "
					  "additional IMV IDs from the TNCS", this->id, this->name);
		return TNC_RESULT_ILLEGAL_OPERATION;
	}
	while (count > 0)
	{
		result = this->reserve_additional_id(this->id, &id);
		if (result != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_IMV, "IMV %u \"%s\" failed to reserve %d additional IMV IDs",
						  this->id, this->name, count);
			return result;
		}
		count--;

		/* store the scalar value in the pointer */
		pointer = (void*)id;
		this->additional_ids->insert_last(this->additional_ids, pointer);
		DBG2(DBG_IMV, "IMV %u \"%s\" reserved additional ID %u",
					  this->id, this->name, id);
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imv_agent_t, count_additional_ids, int,
	private_imv_agent_t *this)
{
	return	this->additional_ids->get_count(this->additional_ids);
}

METHOD(imv_agent_t, create_id_enumerator, enumerator_t*,
	private_imv_agent_t *this)
{
	return this->additional_ids->create_enumerator(this->additional_ids);
}

METHOD(imv_agent_t, destroy, void,
	private_imv_agent_t *this)
{
	DBG1(DBG_IMV, "IMV %u \"%s\" terminated", this->id, this->name);
	this->additional_ids->destroy(this->additional_ids);
	this->connections->destroy_offset(this->connections,
									  offsetof(imv_state_t, destroy));
	this->connection_lock->destroy(this->connection_lock);
	free(this);

	/* decrease the reference count or terminate */
	libimcv_deinit();
}

/**
 * Described in header.
 */
imv_agent_t *imv_agent_create(const char *name,
							  pen_t vendor_id, u_int32_t subtype,
							  TNC_IMVID id, TNC_Version *actual_version)
{
	private_imv_agent_t *this;

	/* initialize  or increase the reference count */
	if (!libimcv_init())
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.bind_functions = _bind_functions,
			.create_state = _create_state,
			.delete_state = _delete_state,
			.change_state = _change_state,
			.get_state = _get_state,
			.send_message = _send_message,
			.receive_message = _receive_message,
			.set_recommendation = _set_recommendation,
			.provide_recommendation = _provide_recommendation,
			.reserve_additional_ids = _reserve_additional_ids,
			.count_additional_ids = _count_additional_ids,
			.create_id_enumerator = _create_id_enumerator,
			.destroy = _destroy,
		},
		.name = name,
		.vendor_id = vendor_id,
		.subtype = subtype,
		.max_msg_len = 65490,
		.id = id,
		.additional_ids = linked_list_create(),
		.connections = linked_list_create(),
		.connection_lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	*actual_version = TNC_IFIMV_VERSION_1;
	DBG1(DBG_IMV, "IMV %u \"%s\" initialized", this->id, this->name);

	return &this->public;
}


