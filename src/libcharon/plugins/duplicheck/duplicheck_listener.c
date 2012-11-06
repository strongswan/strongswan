/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "duplicheck_listener.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/hashtable.h>
#include <encoding/payloads/delete_payload.h>
#include <processing/jobs/delete_ike_sa_job.h>

typedef struct private_duplicheck_listener_t private_duplicheck_listener_t;

/**
 * Private data of an duplicheck_listener_t object.
 */
struct private_duplicheck_listener_t {

	/**
	 * Public duplicheck_listener_t interface.
	 */
	duplicheck_listener_t public;

	/**
	 * Socket to send notifications to
	 */
	duplicheck_notify_t *notify;

	/**
	 * Mutex to lock hashtables
	 */
	mutex_t *mutex;

	/**
	 * Hashtable of active IKE_SAs, identification_t => entry_t
	 */
	hashtable_t *active;

	/**
	 * Hashtable with active liveness checks, identification_t => entry_t
	 */
	hashtable_t *checking;
};

/**
 * Entry for hashtables
 */
typedef struct {
	/** peer identity */
	identification_t *id;
	/** IKE_SA identifier */
	ike_sa_id_t *sa;
} entry_t;

/**
 * Destroy a hashtable entry
 */
static void entry_destroy(entry_t *this)
{
	this->id->destroy(this->id);
	this->sa->destroy(this->sa);
	free(this);
}

/**
 * Hashtable hash function
 */
static u_int hash(identification_t *key)
{
	return chunk_hash(key->get_encoding(key));
}

/**
 * Hashtable equals function
 */
static bool equals(identification_t *a, identification_t *b)
{
	return a->equals(a, b);
}

METHOD(listener_t, ike_rekey, bool,
	private_duplicheck_listener_t *this, ike_sa_t *old, ike_sa_t *new)
{
	identification_t *id;
	ike_sa_id_t *sa;
	entry_t *entry;

	sa = new->get_id(new);
	id = new->get_other_id(new);

	INIT(entry,
		.id = id->clone(id),
		.sa = sa->clone(sa),
	);
	this->mutex->lock(this->mutex);
	entry = this->active->put(this->active, entry->id, entry);
	this->mutex->unlock(this->mutex);
	if (entry)
	{
		entry_destroy(entry);
	}
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_duplicheck_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	identification_t *id;
	ike_sa_id_t *sa;
	entry_t *entry;
	job_t *job;

	sa = ike_sa->get_id(ike_sa);
	id = ike_sa->get_other_id(ike_sa);

	if (up)
	{
		INIT(entry,
			.id = id->clone(id),
			.sa = sa->clone(sa),
		);
		this->mutex->lock(this->mutex);
		entry = this->active->put(this->active, entry->id, entry);
		this->mutex->unlock(this->mutex);
		if (entry)
		{
			DBG1(DBG_CFG, "detected duplicate IKE_SA for '%Y', "
				 "triggering delete for old IKE_SA", id);
			job = (job_t*)delete_ike_sa_job_create(entry->sa, TRUE);
			this->mutex->lock(this->mutex);
			entry = this->checking->put(this->checking, entry->id, entry);
			this->mutex->unlock(this->mutex);
			lib->processor->queue_job(lib->processor, job);
			if (entry)
			{
				entry_destroy(entry);
			}
		}
	}
	else
	{
		this->mutex->lock(this->mutex);
		entry = this->checking->remove(this->checking, id);
		this->mutex->unlock(this->mutex);
		if (entry)
		{
			DBG1(DBG_CFG, "delete for duplicate IKE_SA '%Y' timed out, "
				 "keeping new IKE_SA", id);
			entry_destroy(entry);
		}
		else
		{
			this->mutex->lock(this->mutex);
			entry = this->active->remove(this->active, id);
			this->mutex->unlock(this->mutex);
			if (entry)
			{
				entry_destroy(entry);
			}
		}
	}
	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_duplicheck_listener_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	if (incoming && plain && !message->get_request(message))
	{
		identification_t *id;
		entry_t *entry;

		id = ike_sa->get_other_id(ike_sa);
		this->mutex->lock(this->mutex);
		entry = this->checking->remove(this->checking, id);
		this->mutex->unlock(this->mutex);
		if (entry)
		{
			DBG1(DBG_CFG, "got a response on a duplicate IKE_SA for '%Y', "
				 "deleting new IKE_SA", id);
			charon->bus->alert(charon->bus, ALERT_UNIQUE_KEEP);
			entry_destroy(entry);
			this->mutex->lock(this->mutex);
			entry = this->active->remove(this->active, id);
			this->mutex->unlock(this->mutex);
			if (entry)
			{
				lib->processor->queue_job(lib->processor,
						(job_t*)delete_ike_sa_job_create(entry->sa, TRUE));
				entry_destroy(entry);
			}
			this->notify->send(this->notify, id);
		}
	}
	return TRUE;
}

METHOD(duplicheck_listener_t, destroy, void,
	private_duplicheck_listener_t *this)
{
	enumerator_t *enumerator;
	identification_t *key;
	entry_t *value;

	enumerator = this->active->create_enumerator(this->active);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		entry_destroy(value);
	}
	enumerator->destroy(enumerator);

	enumerator = this->checking->create_enumerator(this->checking);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		entry_destroy(value);
	}
	enumerator->destroy(enumerator);

	this->active->destroy(this->active);
	this->checking->destroy(this->checking);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
duplicheck_listener_t *duplicheck_listener_create(duplicheck_notify_t *notify)
{
	private_duplicheck_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_rekey = _ike_rekey,
				.ike_updown = _ike_updown,
				.message = _message_hook,
			},
			.destroy = _destroy,
		},
		.notify = notify,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.active = hashtable_create((hashtable_hash_t)hash,
								   (hashtable_equals_t)equals, 32),
		.checking = hashtable_create((hashtable_hash_t)hash,
									 (hashtable_equals_t)equals, 2),
	);

	return &this->public;
}
