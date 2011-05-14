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

#include <tnc/imv/imv_recommendations.h>

#include <debug.h>
#include <daemon.h>
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

	/**
	 * TNCCS send message function
	 */
	tnccs_send_message_t send_message;

	/**
	 * TNCCS request handshake retry flag
	 */
	bool *request_handshake_retry;

	/**
	 * collection of IMV recommendations
	 */
	recommendations_t *recs;
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
	 * rwlock to lock the TNCCS protocol entries
	 */
	rwlock_t *protocol_lock;

	/**
	 * connection ID counter
	 */
	TNC_ConnectionID connection_id;

	/**
	 * list of TNCCS connection entries
	 */
	linked_list_t *connections;

	/**
	 * rwlock to lock TNCCS connection entries
	 */
	rwlock_t *connection_lock;

};

METHOD(tnccs_manager_t, add_method, void,
	private_tnccs_manager_t *this, tnccs_type_t type,
	tnccs_constructor_t constructor)
{
	tnccs_entry_t *entry;

	entry = malloc_thing(tnccs_entry_t);
	entry->type = type;
	entry->constructor = constructor;

	this->protocol_lock->write_lock(this->protocol_lock);
	this->protocols->insert_last(this->protocols, entry);
	this->protocol_lock->unlock(this->protocol_lock);
}

METHOD(tnccs_manager_t, remove_method, void,
	private_tnccs_manager_t *this, tnccs_constructor_t constructor)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;

	this->protocol_lock->write_lock(this->protocol_lock);
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
	this->protocol_lock->unlock(this->protocol_lock);
}

METHOD(tnccs_manager_t, create_instance, tnccs_t*,
	private_tnccs_manager_t *this, tnccs_type_t type, bool is_server)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;
	tnccs_t *protocol = NULL;

	this->protocol_lock->read_lock(this->protocol_lock);
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
	this->protocol_lock->unlock(this->protocol_lock);

	return protocol;
}

METHOD(tnccs_manager_t, create_connection, TNC_ConnectionID,
	private_tnccs_manager_t *this, tnccs_t *tnccs, 
	tnccs_send_message_t send_message, bool* request_handshake_retry,
	recommendations_t **recs)
{
	tnccs_connection_entry_t *entry;

	entry = malloc_thing(tnccs_connection_entry_t);
	entry->tnccs = tnccs;
	entry->send_message = send_message;
	entry->request_handshake_retry = request_handshake_retry;
	if (recs)
	{
		/* we assume a TNC Server needing recommendations from IMVs */
		if (!charon->imvs)
		{
 			DBG1(DBG_TNC, "no IMV manager available!");
			free(entry);
			return 0;
		}
		entry->recs = charon->imvs->create_recommendations(charon->imvs);
		*recs = entry->recs;
	}
	else
	{
		/* we assume a TNC Client */
		if (!charon->imcs)
		{
			DBG1(DBG_TNC, "no IMC manager available!");
			free(entry);
			return 0;
		}
		entry->recs = NULL;
	}
	this->connection_lock->write_lock(this->connection_lock);
	entry->id = ++this->connection_id;
	this->connections->insert_last(this->connections, entry);
	this->connection_lock->unlock(this->connection_lock);

	DBG1(DBG_TNC, "assigned TNCCS Connection ID %u", entry->id);
	return entry->id;
}

METHOD(tnccs_manager_t, remove_connection, void,
	private_tnccs_manager_t *this, TNC_ConnectionID id, bool is_server)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;

	if (is_server)
	{
		if (charon->imvs)
		{
			charon->imvs->notify_connection_change(charon->imvs, id,
										TNC_CONNECTION_STATE_DELETE);
		}
	}
	else
	{
		if (charon->imcs)
		{
			charon->imcs->notify_connection_change(charon->imcs, id,
										TNC_CONNECTION_STATE_DELETE);
		}
	}

	this->connection_lock->write_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			this->connections->remove_at(this->connections, enumerator);
			if (entry->recs)
			{
				entry->recs->destroy(entry->recs);
			}
			free(entry);
			DBG1(DBG_TNC, "removed TNCCS Connection ID %u", id);
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);
}

METHOD(tnccs_manager_t,	request_handshake_retry, TNC_Result,
	private_tnccs_manager_t *this, bool is_imc, TNC_UInt32 imcv_id,
												TNC_ConnectionID id,
												TNC_RetryReason reason)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;

	if (id == TNC_CONNECTIONID_ANY)
	{
		DBG2(DBG_TNC, "%s %u requests handshake retry for all connections "
					  "(reason: %u)", is_imc ? "IMC":"IMV", reason);
	}
	else
	{
		DBG2(DBG_TNC, "%s %u requests handshake retry for Connection ID %u "
					  "(reason: %u)", is_imc ? "IMC":"IMV", imcv_id, id, reason);
	}
	this->connection_lock->read_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == TNC_CONNECTIONID_ANY || id == entry->id)
		{
			*entry->request_handshake_retry = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	return TNC_RESULT_SUCCESS;
}

METHOD(tnccs_manager_t, send_message, TNC_Result,
	private_tnccs_manager_t *this, TNC_IMCID imc_id, TNC_IMVID imv_id,
								   TNC_ConnectionID id,
								   TNC_BufferReference msg,
								   TNC_UInt32 msg_len,
								   TNC_MessageType msg_type)

{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	tnccs_send_message_t send_message = NULL;
	tnccs_t *tnccs = NULL;
	TNC_VendorID msg_vid;
	TNC_MessageSubtype msg_subtype;

	msg_vid = (msg_type >> 8) & TNC_VENDORID_ANY;
	msg_subtype = msg_type & TNC_SUBTYPE_ANY;

	if (msg_vid == TNC_VENDORID_ANY || msg_subtype == TNC_SUBTYPE_ANY)
	{
		DBG1(DBG_TNC, "not sending message of invalid type 0x%08x", msg_type);
		return TNC_RESULT_INVALID_PARAMETER;
	}

	this->connection_lock->read_lock(this->connection_lock);
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
	this->connection_lock->unlock(this->connection_lock);

	if (tnccs && send_message)
	{
		return send_message(tnccs, imc_id, imv_id, msg, msg_len, msg_type);
	}
	return TNC_RESULT_FATAL;
}

METHOD(tnccs_manager_t, provide_recommendation, TNC_Result,
	private_tnccs_manager_t *this, TNC_IMVID imv_id,
								   TNC_ConnectionID id,
								   TNC_IMV_Action_Recommendation rec,
								   TNC_IMV_Evaluation_Result eval)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	recommendations_t *recs = NULL;

	this->connection_lock->read_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			recs = entry->recs;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	if (recs)
	{
		recs->provide_recommendation(recs, imv_id, rec, eval);
		return TNC_RESULT_SUCCESS;
	 }
	return TNC_RESULT_FATAL;
}

METHOD(tnccs_manager_t, get_attribute, TNC_Result,
	private_tnccs_manager_t *this, TNC_IMVID imv_id,
								   TNC_ConnectionID id,
								   TNC_AttributeID attribute_id,
								   TNC_UInt32 buffer_len,
								   TNC_BufferReference buffer,
								   TNC_UInt32 *out_value_len)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	recommendations_t *recs = NULL;

	if (id == TNC_CONNECTIONID_ANY ||
		attribute_id != TNC_ATTRIBUTEID_PREFERRED_LANGUAGE)
	{
		return TNC_RESULT_INVALID_PARAMETER;
	}

	this->connection_lock->read_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			recs = entry->recs;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	if (recs)
	{
		chunk_t pref_lang;

		pref_lang = recs->get_preferred_language(recs);
		if (pref_lang.len == 0)
		{
			return TNC_RESULT_INVALID_PARAMETER;
		}
		*out_value_len = pref_lang.len;
		if (buffer && buffer_len <= pref_lang.len)
		{
			memcpy(buffer, pref_lang.ptr, pref_lang.len);
		}
		return TNC_RESULT_SUCCESS;
	 }
	return TNC_RESULT_INVALID_PARAMETER;
}

METHOD(tnccs_manager_t, set_attribute, TNC_Result,
	private_tnccs_manager_t *this, TNC_IMVID imv_id,
								   TNC_ConnectionID id,
								   TNC_AttributeID attribute_id,
								   TNC_UInt32 buffer_len,
								   TNC_BufferReference buffer)
{
	enumerator_t *enumerator;
	tnccs_connection_entry_t *entry;
	recommendations_t *recs = NULL;

	if (id == TNC_CONNECTIONID_ANY ||
		(attribute_id != TNC_ATTRIBUTEID_REASON_STRING &&
		 attribute_id != TNC_ATTRIBUTEID_REASON_LANGUAGE))
	{
		return TNC_RESULT_INVALID_PARAMETER;
	}

	this->connection_lock->read_lock(this->connection_lock);
	enumerator = this->connections->create_enumerator(this->connections);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (id == entry->id)
		{
			recs = entry->recs;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->connection_lock->unlock(this->connection_lock);

	if (recs)
	{
		chunk_t attribute = { buffer, buffer_len };

		if (attribute_id == TNC_ATTRIBUTEID_REASON_STRING)
		{
			return recs->set_reason_string(recs, imv_id, attribute);
		}
		else
		{
			return recs->set_reason_language(recs, imv_id, attribute);
		}
	}
	return TNC_RESULT_INVALID_PARAMETER;
}

METHOD(tnccs_manager_t, destroy, void,
	private_tnccs_manager_t *this)
{
	this->protocols->destroy_function(this->protocols, free);
	this->protocol_lock->destroy(this->protocol_lock);
	this->connections->destroy_function(this->connections, free);
	this->connection_lock->destroy(this->connection_lock);
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
				.request_handshake_retry = _request_handshake_retry,
				.send_message = _send_message,
				.provide_recommendation = _provide_recommendation,
				.get_attribute = _get_attribute,
				.set_attribute = _set_attribute,
				.destroy = _destroy,
			},
			.protocols = linked_list_create(),
			.connections = linked_list_create(),
			.protocol_lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
			.connection_lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

