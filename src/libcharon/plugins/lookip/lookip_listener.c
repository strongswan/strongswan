/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "lookip_listener.h"

#include <daemon.h>
#include <utils/hashtable.h>
#include <threading/rwlock.h>

typedef struct private_lookip_listener_t private_lookip_listener_t;

/**
 * Private data of an lookip_listener_t object.
 */
struct private_lookip_listener_t {

	/**
	 * Public lookip_listener_t interface.
	 */
	lookip_listener_t public;

	/**
	 * Lock for hashtable
	 */
	rwlock_t *lock;

	/**
	 * Hashtable with entries: host_t => entry_t
	 */
	hashtable_t *entries;
};

/**
 * Hashtable entry
 */
typedef struct {
	/** virtual IP, serves as lookup key */
	host_t *vip;
	/** peers external address */
	host_t *other;
	/** peer (EAP-)Identity */
	identification_t *id;
	/** associated connection name */
	char *name;
} entry_t;

/**
 * Destroy a hashtable entry
 */
static void entry_destroy(entry_t *entry)
{
	entry->vip->destroy(entry->vip);
	entry->other->destroy(entry->other);
	entry->id->destroy(entry->id);
	free(entry->name);
	free(entry);
}

/**
 * Hashtable hash function
 */
static u_int hash(host_t *key)
{
	return chunk_hash(key->get_address(key));
}

/**
 * Hashtable equals function
 */
static bool equals(host_t *a, host_t *b)
{
	return a->ip_equals(a, b);
}

/**
 * Add a new entry to the hashtable
 */
static void add_entry(private_lookip_listener_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	host_t *vip, *other;
	identification_t *id;
	entry_t *entry;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (enumerator->enumerate(enumerator, &vip))
	{
		other = ike_sa->get_other_host(ike_sa);
		id = ike_sa->get_other_eap_id(ike_sa);

		INIT(entry,
			.vip = vip->clone(vip),
			.other = other->clone(other),
			.id = id->clone(id),
			.name = strdup(ike_sa->get_name(ike_sa)),
		);

		this->lock->write_lock(this->lock);
		entry = this->entries->put(this->entries, entry->vip, entry);
		this->lock->unlock(this->lock);
		if (entry)
		{
			entry_destroy(entry);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Remove an entry from the hashtable
 */
static void remove_entry(private_lookip_listener_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	host_t *vip;
	entry_t *entry;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (enumerator->enumerate(enumerator, &vip))
	{
		this->lock->write_lock(this->lock);
		entry = this->entries->remove(this->entries, vip);
		this->lock->unlock(this->lock);
		if (entry)
		{
			entry_destroy(entry);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(listener_t, message_hook, bool,
	private_lookip_listener_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	if (plain && ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		!incoming && !message->get_request(message))
	{
		if (ike_sa->get_version(ike_sa) == IKEV1 &&
			message->get_exchange_type(message) == TRANSACTION)
		{
			add_entry(this, ike_sa);
		}
		if (ike_sa->get_version(ike_sa) == IKEV2 &&
			message->get_exchange_type(message) == IKE_AUTH)
		{
			add_entry(this, ike_sa);
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_lookip_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	if (!up)
	{
		remove_entry(this, ike_sa);
	}
	return TRUE;
}

METHOD(lookip_listener_t, destroy, void,
	private_lookip_listener_t *this)
{
	this->entries->destroy(this->entries);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
lookip_listener_t *lookip_listener_create()
{
	private_lookip_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.message = _message_hook,
				.ike_updown = _ike_updown,
			},
			.destroy = _destroy,
		},
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.entries = hashtable_create((hashtable_hash_t)hash,
									(hashtable_equals_t)equals, 32),
	);

	return &this->public;
}
