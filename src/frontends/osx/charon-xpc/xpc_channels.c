/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "xpc_channels.h"

#include <collections/hashtable.h>
#include <threading/rwlock.h>
#include <daemon.h>

typedef struct private_xpc_channels_t private_xpc_channels_t;

/**
 * Private data of an xpc_channels_t object.
 */
struct private_xpc_channels_t {

	/**
	 * Public xpc_channels_t interface.
	 */
	xpc_channels_t public;

	/**
	 * Registered channels, IKE_SA unique ID => entry_t
	 */
	hashtable_t *channels;

	/**
	 * Lock for channels list
	 */
	rwlock_t *lock;
};

/**
 * Channel entry
 */
typedef struct {
	/* XPC channel to App */
	xpc_connection_t conn;
	/* associated IKE_SA unique identifier */
	uintptr_t sa;
} entry_t;

/**
 * Clean up an entry, cancelling connection
 */
static void destroy_entry(entry_t *entry)
{
	xpc_connection_suspend(entry->conn);
	xpc_connection_cancel(entry->conn);
	xpc_release(entry->conn);
	free(entry);
}

/**
 * Remove an entry for a given XPC connection
 */
static void remove_conn(private_xpc_channels_t *this, xpc_connection_t conn)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->channels->create_enumerator(this->channels);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (xpc_equal(entry->conn, conn))
		{
			this->channels->remove(this->channels, enumerator);
			destroy_entry(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Handle a request message from App
 */
static void handle(private_xpc_channels_t *this, xpc_object_t request)
{
	/* TODO: */
}

METHOD(xpc_channels_t, add, void,
	private_xpc_channels_t *this, xpc_connection_t conn, u_int32_t ike_sa)
{
	entry_t *entry;

	INIT(entry,
		.conn = conn,
		.sa = ike_sa,
	);

	xpc_connection_set_event_handler(entry->conn, ^(xpc_object_t event) {

		if (event == XPC_ERROR_CONNECTION_INVALID ||
			event == XPC_ERROR_CONNECTION_INTERRUPTED)
		{
			remove_conn(this, entry->conn);
		}
		else
		{
			handle(this, event);
		}
	});

	this->lock->write_lock(this->lock);
	this->channels->put(this->channels, (void*)entry->sa, entry);
	this->lock->unlock(this->lock);

	xpc_connection_resume(conn);
}

METHOD(listener_t, ike_rekey, bool,
	private_xpc_channels_t *this, ike_sa_t *old, ike_sa_t *new)
{
	entry_t *entry;
	uintptr_t sa;

	sa = old->get_unique_id(old);
	this->lock->write_lock(this->lock);
	entry = this->channels->remove(this->channels, (void*)sa);
	if (entry)
	{
		entry->sa = new->get_unique_id(new);
		this->channels->put(this->channels, (void*)entry->sa, entry);
	}
	this->lock->unlock(this->lock);

	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_xpc_channels_t *this, ike_sa_t *ike_sa, bool up)
{
	xpc_object_t msg;
	entry_t *entry;
	uintptr_t sa;

	sa = ike_sa->get_unique_id(ike_sa);
	if (up)
	{
		this->lock->read_lock(this->lock);
		entry = this->channels->get(this->channels, (void*)sa);
		if (entry)
		{
			msg = xpc_dictionary_create(NULL, NULL, 0);
			xpc_dictionary_set_string(msg, "type", "event");
			xpc_dictionary_set_string(msg, "event", "up");
			xpc_connection_send_message(entry->conn, msg);
			xpc_release(msg);
		}
		this->lock->unlock(this->lock);
	}
	else
	{
		this->lock->write_lock(this->lock);
		entry = this->channels->remove(this->channels, (void*)sa);
		this->lock->unlock(this->lock);
		if (entry)
		{
			msg = xpc_dictionary_create(NULL, NULL, 0);
			xpc_dictionary_set_string(msg, "type", "event");
			xpc_dictionary_set_string(msg, "event", "down");
			xpc_connection_send_message(entry->conn, msg);
			xpc_release(msg);
			xpc_connection_send_barrier(entry->conn, ^() {
				destroy_entry(entry);
			});
		}
	}
	return TRUE;
}

METHOD(xpc_channels_t, destroy, void,
	private_xpc_channels_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;

	enumerator = this->channels->create_enumerator(this->channels);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		destroy_entry(entry);
	}
	enumerator->destroy(enumerator);

	this->channels->destroy(this->channels);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
xpc_channels_t *xpc_channels_create()
{
	private_xpc_channels_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
			},
			.add = _add,
			.destroy = _destroy,
		},
		.channels = hashtable_create(hashtable_hash_ptr,
									 hashtable_equals_ptr, 4),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
