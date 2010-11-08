/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "tnccs_manager.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_tnccs_manager_t private_tnccs_manager_t;
typedef struct tnccs_entry_t tnccs_entry_t;
typedef struct tnccs_connection_entry_t tnccs_connection_entry_t;

/**
 * TNCCS constructor entry
 */
struct tnccs_entry_t {

	/**
	 * TNCCS protocol type
	 */
	tnccs_type_t type;

	/**
	 * constructor function to create instance
	 */
	tnccs_constructor_t constructor;
};

/**
 * TNCCS connection entry
 */
struct tnccs_connection_entry_t {

	/**
	 * TNCCS connection ID
	 */
	TNC_ConnectionID id;

	/**
	 * TNCCS instance
	 */
	tnccs_t *tnccs;

	/** TNCCS send message function
	 *
	 */
	tnccs_send_message_t send_message;

	/** TNCS provide recommendation function
	 *
	 */
	tnccs_provide_recommendation_t provide_recommendation;
};

/**
 * private data of tnccs_manager
 */
struct private_tnccs_manager_t {

	/**
	 * public functions
	 */
	tnccs_manager_t public;

	/**
	 * list of TNCCS protocol entries
	 */
	linked_list_t *protocols;

	/**
	 * connection ID counter
	 */
	TNC_ConnectionID connection_id;

	/**
	 * list of TNCCS connection entries
	 */
	linked_list_t *connections;

	/**
	 * rwlock to lock TNCCS protocol and connection entries
	 */
	rwlock_t *lock;

};

METHOD(tnccs_manager_t, add_method, void,
	private_tnccs_manager_t *this, tnccs_type_t type,
	tnccs_constructor_t constructor)
{
	tnccs_entry_t *entry = malloc_thing(tnccs_entry_t);

	entry->type = type;
	entry->constructor = constructor;

	this->lock->write_lock(this->lock);
	this->protocols->insert_last(this->protocols, entry);
	this->lock->unlock(this->lock);
}

METHOD(tnccs_manager_t, remove_method, void,
	private_tnccs_manager_t *this, tnccs_constructor_t constructor)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->protocols->create_enumerator(this->protocols);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (constructor == entry->constructor)
		{
			this->protocols->remove_at(this->protocols, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(tnccs_manager_t, create_instance, tnccs_t*,
	private_tnccs_manager_t *this, tnccs_type_t type, bool is_server)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;
	tnccs_t *protocol = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->protocols->create_enumerator(this->protocols);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (type == entry->type)
		{
			protocol = entry->constructor(is_server);
			if (protocol)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return protocol;
}

METHOD(tnccs_manager_t, create_connection, TNC_ConnectionID,
	private_tnccs_manager_t *this, tnccs_t *tnccs,
	tnccs_send_message_t send_message)
{
	tnccs_connection_entry_t *entry = malloc_thing(tnccs_connection_entry_t);

	entry->id = ++this->connection_id;
	entry->tnccs = tnccs;
	entry->send_message = send_message;

	this->lock->write_lock(this->lock);
	this->connections->insert_last(this->connections, entry);
	this->lock->unlock(this->lock);

	DBG1(DBG_TNC, "assigned TNCCS Connection ID %u", entry->id);
	return entry->id;
}

METHOD(tnccs_manager_t, remove_connection, void,
	private_tnccs_manager_t *this, TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			this->connections->remove_at(this->connections, enumerator);
			free(entry);
			DBG1(DBG_TNC, "removed TNCCS Connection ID %u", id);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(tnccs_manager_t, send_message, TNC_Result,
	private_tnccs_manager_t *this, TNC_ConnectionID id,
								   TNC_BufferReference message,
								   TNC_UInt32 message_len,
								   TNC_MessageType message_type)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	tnccs_send_message_t send_message = NULL;
	tnccs_t *tnccs = NULL;

	this->lock->write_lock(this->lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			tnccs = entry->tnccs;
			send_message = entry->send_message;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (tnccs && send_message)
	{
		send_message(tnccs, message, message_len, message_type);
		return TNC_RESULT_SUCCESS;
	 }
	return TNC_RESULT_FATAL;
}

METHOD(tnccs_manager_t, provide_recommendation, TNC_Result,
	private_tnccs_manager_t *this, TNC_IMVID imv_id,
								   TNC_ConnectionID id,
								   TNC_IMV_Action_Recommendation recommendation,
								   TNC_IMV_Evaluation_Result evaluation)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	tnccs_provide_recommendation_t provide_recommendation = NULL;
	tnccs_t *tnccs = NULL;

	this->lock->write_lock(this->lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			tnccs = entry->tnccs;
			provide_recommendation = entry->provide_recommendation;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (tnccs && provide_recommendation)
	{
		provide_recommendation(tnccs, imv_id, recommendation, evaluation);
		return TNC_RESULT_SUCCESS;
	 }
	return TNC_RESULT_FATAL;
}

METHOD(tnccs_manager_t, destroy, void,
	private_tnccs_manager_t *this)
{
	this->protocols->destroy_function(this->protocols, free);
	this->connections->destroy_function(this->connections, free);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * See header
 */
tnccs_manager_t *tnccs_manager_create()
{
	private_tnccs_manager_t *this;

	INIT(this,
			.public = {
				.add_method = _add_method,
				.remove_method = _remove_method,
				.create_instance = _create_instance,
				.create_connection = _create_connection,
				.remove_connection = _remove_connection,
				.send_message = _send_message,
				.provide_recommendation = _provide_recommendation,
				.destroy = _destroy,
			},
			.protocols = linked_list_create(),
			.connections = linked_list_create(),
			.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

