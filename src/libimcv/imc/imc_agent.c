/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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
#include "imc_agent.h"

#include <tncif_names.h>

#include <debug.h>
#include <utils/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_imc_agent_t private_imc_agent_t;

/**
 * Private data of an imc_agent_t object.
 */
struct private_imc_agent_t {

	/**
	 * Public members of imc_agent_t
	 */
	imc_agent_t public;

	/**
	 * name of IMC
	 */
	const char *name;

	/**
	 * message type of IMC
	 */
	TNC_MessageType type;

	/**
	 * ID of IMC as assigned by TNCC
	 */
	TNC_IMCID id;

	/**
	 * list of TNCC connection entries
	 */
	linked_list_t *connections;

	/**
	 * rwlock to lock TNCS connection entries
	 */
	rwlock_t *connection_lock;

	/**
	 * Inform a TNCS about the set of message types the IMC is able to receive 
	 *
	 * @param imc_id			IMC ID assigned by TNCC
	 * @param supported_types	list of supported message types
	 * @param type_count		number of list elements
	 * @return					TNC result code
	 */
	TNC_Result (*report_message_types)(TNC_IMCID imc_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count);

	/**
	 * Call when an IMC-IMC message is to be sent
	 *
	 * @param imc_id			IMC ID assigned by TNCC
	 * @param connection_id		network connection ID assigned by TNCC
	 * @param msg				message to send
	 * @param msg_len			message length in bytes
	 * @param msg_type			message type
	 * @return					TNC result code
	 */
	TNC_Result (*send_message)(TNC_IMCID imc_id,
							   TNC_ConnectionID connection_id,
							   TNC_BufferReference msg,
							   TNC_UInt32 msg_len,
							   TNC_MessageType msg_type);
};

METHOD(imc_agent_t, bind_functions, TNC_Result,
	private_imc_agent_t *this, TNC_TNCC_BindFunctionPointer bind_function)
{
	if (!bind_function)
	{
		DBG1(DBG_IMC, "TNC client failed to provide bind function");
		return TNC_RESULT_INVALID_PARAMETER;
	}
	if (bind_function(this->id, "TNC_TNCC_ReportMessageTypes",
			(void**)&this->report_message_types) != TNC_RESULT_SUCCESS)
	{
		this->report_message_types = NULL;
	}
	if (bind_function(this->id, "TNC_TNCC_RequestHandshakeRetry",
			(void**)&this->public.request_handshake_retry) != TNC_RESULT_SUCCESS)
	{
		this->public.request_handshake_retry = NULL;
	}
	if (bind_function(this->id, "TNC_TNCC_SendMessage",
			(void**)&this->send_message) != TNC_RESULT_SUCCESS)
	{
		this->send_message = NULL;
	}
	DBG2(DBG_IMC, "IMC %u \"%s\" provided with bind function",
				  this->id, this->name);

	if (this->report_message_types)
	{
		this->report_message_types(this->id, &this->type, 1);
	}
	return TNC_RESULT_SUCCESS;
}

/**
 * finds a connection state based on its Connection ID
 */
static imc_state_t* find_connection(private_imc_agent_t *this,
									 TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	imc_state_t *state, *found = NULL;

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
static bool delete_connection(private_imc_agent_t *this, TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	imc_state_t *state;
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

METHOD(imc_agent_t, create_state, TNC_Result,
	private_imc_agent_t *this, imc_state_t *state)
{
	TNC_ConnectionID connection_id;

	connection_id = state->get_connection_id(state);
	if (find_connection(this, connection_id))
	{
		DBG1(DBG_IMC, "IMC %u \"%s\" already created a state for Connection ID %u",
					   this->id, this->name, connection_id);
		state->destroy(state);
		return TNC_RESULT_OTHER;
	}
	this->connection_lock->write_lock(this->connection_lock);
	this->connections->insert_last(this->connections, state);
	this->connection_lock->unlock(this->connection_lock);
	DBG2(DBG_IMC, "IMC %u \"%s\" created a state for Connection ID %u",
				  this->id, this->name, connection_id);
	return TNC_RESULT_SUCCESS;
}

METHOD(imc_agent_t, delete_state, TNC_Result,
	private_imc_agent_t *this, TNC_ConnectionID connection_id)
{
	if (!delete_connection(this, connection_id))
	{
		DBG1(DBG_IMC, "IMC %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return TNC_RESULT_FATAL;
	}
	DBG2(DBG_IMC, "IMC %u \"%s\" deleted the state of Connection ID %u",
				  this->id, this->name, connection_id);
	return TNC_RESULT_SUCCESS;
}

METHOD(imc_agent_t, change_state, TNC_Result,
	private_imc_agent_t *this, TNC_ConnectionID connection_id,
							   TNC_ConnectionState new_state)
{
	imc_state_t *state;

	switch (new_state)
	{
		case TNC_CONNECTION_STATE_HANDSHAKE:
		case TNC_CONNECTION_STATE_ACCESS_ALLOWED:
		case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
		case TNC_CONNECTION_STATE_ACCESS_NONE:
			state = find_connection(this, connection_id);
			if (!state)
			{
				DBG1(DBG_IMC, "IMC %u \"%s\" has no state for Connection ID %u",
							  this->id, this->name, connection_id);
				return TNC_RESULT_FATAL;
			}
			state->change_state(state, new_state);
			DBG2(DBG_IMC, "IMC %u \"%s\" changed state of Connection ID %u to '%N'",
						  this->id, this->name, connection_id,
						  TNC_Connection_State_names, new_state);
			break;
		case TNC_CONNECTION_STATE_CREATE:
			DBG1(DBG_IMC, "state '%N' should be handled by create_state()",
						  TNC_Connection_State_names, new_state);
				return TNC_RESULT_FATAL;
		case TNC_CONNECTION_STATE_DELETE:
			DBG1(DBG_IMC, "state '%N' should be handled by delete_state()",
						  TNC_Connection_State_names, new_state);
				return TNC_RESULT_FATAL;
		default:
			DBG1(DBG_IMC, "IMC %u \"%s\" was notified of unknown state %u "
				 		  "for Connection ID %u",
						  this->id, this->name, new_state, connection_id);
			return TNC_RESULT_INVALID_PARAMETER;		
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imc_agent_t, get_state, bool,
	private_imc_agent_t *this, TNC_ConnectionID connection_id,
							   imc_state_t **state)
{
	*state = find_connection(this, connection_id);
	if (!*state)
	{
		DBG1(DBG_IMC, "IMC %u \"%s\" has no state for Connection ID %u",
					  this->id, this->name, connection_id);
		return FALSE;
	}
	return TRUE;
}

METHOD(imc_agent_t, send_message, TNC_Result,
	private_imc_agent_t *this, TNC_ConnectionID connection_id, chunk_t msg)
{
	if (!this->send_message)
	{
		return TNC_RESULT_FATAL;
	}
	return this->send_message(this->id, connection_id, msg.ptr, msg.len,
							  this->type);
}

METHOD(imc_agent_t, receive_message, TNC_Result,
	private_imc_agent_t *this, TNC_ConnectionID connection_id, chunk_t msg,
	TNC_MessageType msg_type, pa_tnc_msg_t **pa_tnc_msg)
{
	pa_tnc_msg_t *pa_msg, *error_msg;
	pa_tnc_attr_t *error_attr;
	enumerator_t *enumerator;
	TNC_Result result;

	DBG2(DBG_IMV, "IMC %u \"%s\" received message type 0x%08x for Connection ID %u",
				   this->id, this->name, msg_type, connection_id);

	*pa_tnc_msg = NULL;
	pa_msg = pa_tnc_msg_create_from_data(msg);

	switch (pa_msg->process(pa_msg))
	{
		case SUCCESS:
			*pa_tnc_msg = pa_msg;
			break;
		case VERIFY_ERROR:
			if (!this->send_message)
			{
				/* TNCC doen't have a SendMessage() function */
				return TNC_RESULT_FATAL;
			}

			/* build error message */
			error_msg = pa_tnc_msg_create();
			enumerator = pa_msg->create_error_enumerator(pa_msg);
			while (enumerator->enumerate(enumerator, &error_attr))
			{
				error_msg->add_attribute(error_msg,
										 error_attr->get_ref(error_attr));
			}
			enumerator->destroy(enumerator);
			error_msg->build(error_msg);

			/* send error message */
			msg = error_msg->get_encoding(error_msg);
			result = this->send_message(this->id, connection_id,
										msg.ptr, msg.len, msg_type);

			/* clean up */
			error_msg->destroy(error_msg);
			pa_msg->destroy(pa_msg);
			return result;
		case FAILED:
		default:
			pa_msg->destroy(pa_msg);
			return TNC_RESULT_FATAL;
	}
	return TNC_RESULT_SUCCESS;
}

METHOD(imc_agent_t, destroy, void,
	private_imc_agent_t *this)
{
	DBG1(DBG_IMC, "IMC %u \"%s\" terminated", this->id, this->name);
	this->connections->destroy_function(this->connections, free);
	this->connection_lock->destroy(this->connection_lock);
	free(this);

	/* decrease the reference count or terminate */
	libimcv_deinit();
}

/**
 * Described in header.
 */
imc_agent_t *imc_agent_create(const char *name,
							  pen_t vendor_id, u_int32_t subtype,
							  TNC_IMCID id, TNC_Version *actual_version)
{
	private_imc_agent_t *this;

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
			.destroy = _destroy,
		},
		.name = name,
		.type = (vendor_id << 8) | (subtype && 0xff),
		.id = id,
		.connections = linked_list_create(),
		.connection_lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);
	
	*actual_version = TNC_IFIMC_VERSION_1;
	DBG1(DBG_IMC, "IMC %u \"%s\" initialized", this->id, this->name);

	return &this->public;
}

