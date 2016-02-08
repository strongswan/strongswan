/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>
 *
 * Copyright (C) 2015 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
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

#include <time.h>

#include <daemon.h>
#include <collections/array.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>

#include "quota_plugin.h"
#include "quota_accounting.h"

#include "quota_invoke.h"

typedef struct private_quota_accounting_t private_quota_accounting_t;

/**
 * Private data of an quota_accounting_t object.
 */
struct private_quota_accounting_t {

	/**
	 * Public quota_accounting_t interface.
	 */
	quota_accounting_t public;

	/**
	 * Hashtable with sessions, ike_sa_id_t => entry_t
	 */
	hashtable_t *sessions;

	/**
	 * Mutex to lock sessions
	 */
	mutex_t *mutex;

	/**
	 * Disable accounting unless IKE_SA has at least one virtual IP
	 */
	bool acct_req_vip;
};

/**
 * Singleton instance of accounting
 */
static private_quota_accounting_t *singleton = NULL;


/**
 * Add usage stats (modifies a)
 */
static inline void add_usage(usage_t *a, usage_t b)
{
	a->bytes.sent += b.bytes.sent;
	a->bytes.received += b.bytes.received;
	a->packets.sent += b.packets.sent;
	a->packets.received += b.packets.received;
}

/**
 * Subtract usage stats (modifies a)
 */
static inline void sub_usage(usage_t *a, usage_t b)
{
	a->bytes.sent -= b.bytes.sent;
	a->bytes.received -= b.bytes.received;
	a->packets.sent -= b.packets.sent;
	a->packets.received -= b.packets.received;
}

/**
 * Usage stats for a cached/migrated SAs
 */
typedef struct {
	/** unique CHILD_SA identifier */
	u_int32_t id;
	/** usage stats for this SA */
	usage_t usage;
} sa_entry_t;

/**
 * Clone an sa_entry_t
 */
static sa_entry_t *clone_sa(sa_entry_t *sa)
{
	sa_entry_t *this;

	INIT(this,
		.id = sa->id,
		.usage = sa->usage,
	);
	return this;
}

/**
 * Destroy an entry_t
 */
static void destroy_entry(quota_accounting_entry_t *this)
{
	array_destroy_function(this->cached, (void*)free, NULL);
	array_destroy_function(this->migrated, (void*)free, NULL);
	this->id->destroy(this->id);
	free(this);
}


/**
 * Hashtable hash function
 */
static u_int hash(ike_sa_id_t *key)
{
	return key->get_responder_spi(key);
}

/**
 * Hashtable equals function
 */
static bool equals(ike_sa_id_t *a, ike_sa_id_t *b)
{
	return a->equals(a, b);
}

/**
 * Sort cached SAs
 */
static int sa_sort(const void *a, const void *b, void *user)
{
	const sa_entry_t *ra = a, *rb = b;
	return ra->id - rb->id;
}

/**
 * Find a cached SA
 */
static int sa_find(const void *a, const void *b)
{
	return sa_sort(a, b, NULL);
}

/**
 * Update or create usage counters of a cached SA
 */
static void update_sa(quota_accounting_entry_t *entry, u_int32_t id, usage_t usage)
{
	sa_entry_t *sa, lookup;

	lookup.id = id;
	if (array_bsearch(entry->cached, &lookup, sa_find, &sa) == -1)
	{
		INIT(sa,
			.id = id,
		);
		array_insert_create(&entry->cached, ARRAY_TAIL, sa);
		array_sort(entry->cached, sa_sort, NULL);
	}
	sa->usage = usage;
}

/**
 * Update usage counter when a CHILD_SA rekeys/goes down
 */
static void update_usage(private_quota_accounting_t *this,
						 ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	usage_t usage;
	quota_accounting_entry_t *entry;

	child_sa->get_usestats(child_sa, TRUE, NULL, &usage.bytes.received, &usage.packets.received);
	child_sa->get_usestats(child_sa, FALSE, NULL, &usage.bytes.sent, &usage.packets.sent);

	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions, ike_sa->get_id(ike_sa));
	if (entry)
	{
		update_sa(entry, child_sa->get_unique_id(child_sa), usage);
	}
	this->mutex->unlock(this->mutex);
}

/**
 * Collect usage stats for all CHILD_SAs of the given IKE_SA, optionally returns
 * the total number of bytes and packets
 */
static array_t *collect_stats(ike_sa_t *ike_sa, usage_t *total)
{
	enumerator_t *enumerator;
	child_sa_t *child_sa;
	array_t *stats;
	sa_entry_t *sa;
	usage_t usage;

	if (total)
	{
		*total = (usage_t){};
	}

	stats = array_create(0, 0);
	enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		INIT(sa,
			.id = child_sa->get_unique_id(child_sa),
		);
		array_insert(stats, ARRAY_TAIL, sa);
		array_sort(stats, sa_sort, NULL);

		child_sa->get_usestats(child_sa, TRUE, NULL, &usage.bytes.received,
							   &usage.packets.received);
		child_sa->get_usestats(child_sa, FALSE, NULL, &usage.bytes.sent,
							   &usage.packets.sent);
		sa->usage = usage;
		if (total)
		{
			add_usage(total, usage);
		}
	}
	enumerator->destroy(enumerator);
	return stats;
}

/**
 * Cleanup cached SAs
 */
static void cleanup_sas(private_quota_accounting_t *this, ike_sa_t *ike_sa,
						quota_accounting_entry_t *entry)
{
	enumerator_t *enumerator;
	child_sa_t *child_sa;
	sa_entry_t *sa, *found;
	array_t *sas;

	sas = array_create(0, 0);
	enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		INIT(sa,
			.id = child_sa->get_unique_id(child_sa),
		);
		array_insert(sas, ARRAY_TAIL, sa);
		array_sort(sas, sa_sort, NULL);
	}
	enumerator->destroy(enumerator);

	enumerator = array_create_enumerator(entry->cached);
	while (enumerator->enumerate(enumerator, &sa))
	{
		if (array_bsearch(sas, sa, sa_find, &found) == -1)
		{
			/* SA is gone, add its latest stats to the total for this IKE_SA
			 * and remove the cache entry */
			add_usage(&entry->usage, sa->usage);
			array_remove_at(entry->cached, enumerator);
			free(sa);
		}
	}
	enumerator->destroy(enumerator);
	enumerator = array_create_enumerator(entry->migrated);
	while (enumerator->enumerate(enumerator, &sa))
	{
		if (array_bsearch(sas, sa, sa_find, &found) == -1)
		{
			/* SA is gone, subtract stats from the total for this IKE_SA */
			sub_usage(&entry->usage, sa->usage);
			array_remove_at(entry->migrated, enumerator);
			free(sa);
		}
	}
	enumerator->destroy(enumerator);
	array_destroy_function(sas, (void*)free, NULL);
}

/**
 * Get an existing or create a new entry from the locked session table
 */
static quota_accounting_entry_t* get_or_create_entry(private_quota_accounting_t *this,
									ike_sa_id_t *id, u_int32_t unique)
{
	quota_accounting_entry_t *entry;
	time_t now;

	entry = this->sessions->get(this->sessions, id);
	if (!entry)
	{
		now = time_monotonic(NULL);

		INIT(entry,
			.id = id->clone(id),
			.created = now,
			.update = {
				.last = now,
			},
			/* default terminate cause, if none other catched */
			.cause = ACCT_CAUSE_USER_REQUEST,
		);
		this->sessions->put(this->sessions, entry->id, entry);
	}
	return entry;
}


/* forward declaration */
static void schedule_update(private_quota_accounting_t *this,
							 quota_accounting_entry_t *entry);

/**
 * Data passed to do_update() using callback job
 */
typedef struct {
	/** reference to radius accounting */
	private_quota_accounting_t *this;
	/** IKE_SA identifier to update to */
	ike_sa_id_t *id;
} update_data_t;

/**
 * Clean up update data
 */
void destroy_update_data(update_data_t *this)
{
	this->id->destroy(this->id);
	free(this);
}

/**
 * Do an update for entry of given IKE_SA identifier
 */
static job_requeue_t do_update(update_data_t *data)
{
	private_quota_accounting_t *this = data->this;
	usage_t usage;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	quota_accounting_entry_t *entry;
	array_t *stats;
	sa_entry_t *sa, *found;

	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, data->id);
	if (!ike_sa)
	{
		return JOB_REQUEUE_NONE;
	}
	stats = collect_stats(ike_sa, &usage);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);

	/* avoid any races by returning IKE_SA before acquiring lock */

	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions, data->id);
	if (entry)
	{
		entry->update.last = time_monotonic(NULL);

		enumerator = array_create_enumerator(entry->cached);
		while (enumerator->enumerate(enumerator, &sa))
		{
			if (array_bsearch(stats, sa, sa_find, &found) != -1)
			{
				/* SA is still around, update stats (e.g. for IKEv1 where
				 * SA might get used even after rekeying) */
				sa->usage = found->usage;
			}
			else
			{
				/* SA is gone, add its last stats to the total for this IKE_SA
				 * and remove the cache entry */
				add_usage(&entry->usage, sa->usage);
				array_remove_at(entry->cached, enumerator);
				free(sa);
			}
		}
		enumerator->destroy(enumerator);

		enumerator = array_create_enumerator(entry->migrated);
		while (enumerator->enumerate(enumerator, &sa))
		{
			if (array_bsearch(stats, sa, sa_find, &found) != -1)
			{
				/* SA is still around, but we have to compensate */
				sub_usage(&usage, sa->usage);
			}
			else
			{
				/* SA is gone, subtract stats from the total for this IKE_SA */
				sub_usage(&entry->usage, sa->usage);
				array_remove_at(entry->migrated, enumerator);
				free(sa);
			}
		}
		enumerator->destroy(enumerator);

		add_usage(&usage, entry->usage);

		quota_invoke(ike_sa, QUOTA_UPDATE, entry);

		schedule_update(this, entry);
	}
	this->mutex->unlock(this->mutex);
	array_destroy_function(stats, (void*)free, NULL);

	return JOB_REQUEUE_NONE;
}

/**
 * Schedule update for given entry
 */
static void schedule_update(private_quota_accounting_t *this,
							 quota_accounting_entry_t *entry)
{
	if (entry->update.interval)
	{
		update_data_t *data;
		timeval_t tv = {
			.tv_sec = entry->update.last + entry->update.interval,
		};

		INIT(data,
			.this = this,
			.id = entry->id->clone(entry->id),
		);
		lib->scheduler->schedule_job_tv(lib->scheduler,
			(job_t*)callback_job_create_with_prio(
				(callback_job_cb_t)do_update,
				data, (void*)destroy_update_data,
				(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL), tv);
	}
}

/**
 * Check if an IKE_SA has assigned a virtual IP (to peer)
 */
static bool has_vip(ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	host_t *host;
	bool found;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	found = enumerator->enumerate(enumerator, &host);
	enumerator->destroy(enumerator);

	return found;
}


/**
 * Call handler for new session
 */
static void do_start(private_quota_accounting_t *this, ike_sa_t *ike_sa)
{
	quota_accounting_entry_t *entry;

	if (this->acct_req_vip && !has_vip(ike_sa))
	{
		return;
	}

	this->mutex->lock(this->mutex);

	entry = get_or_create_entry(this, ike_sa->get_id(ike_sa), ike_sa->get_unique_id(ike_sa));
	if (entry->start_sent)
	{
		this->mutex->unlock(this->mutex);
		return;
	}
	entry->start_sent = TRUE;

	quota_invoke(ike_sa, QUOTA_START, entry);

	if (!entry->update.interval)
	{
		entry->update.interval = lib->settings->get_time(lib->settings,
					"%s.plugins.quota.update_interval", 0, lib->ns);
		if (entry->update.interval)
		{
			DBG1(DBG_CFG, "scheduling quota Updates every %us", entry->update.interval);
		}
	}
	schedule_update(this, entry);
	this->mutex->unlock(this->mutex);
}


/**
 *  Call handler for closed session
 */
static void do_stop(private_quota_accounting_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	quota_accounting_entry_t *entry;
	sa_entry_t *sa;

	this->mutex->lock(this->mutex);
	entry = this->sessions->remove(this->sessions, ike_sa->get_id(ike_sa));
	this->mutex->unlock(this->mutex);
	if (entry)
	{
		if (!entry->start_sent)
		{	/* we tried to authenticate this peer, but never sent a start */
			destroy_entry(entry);
			return;
		}
		enumerator = array_create_enumerator(entry->cached);
		while (enumerator->enumerate(enumerator, &sa))
		{
			add_usage(&entry->usage, sa->usage);
		}
		enumerator->destroy(enumerator);

		enumerator = array_create_enumerator(entry->migrated);
		while (enumerator->enumerate(enumerator, &sa))
		{
			sub_usage(&entry->usage, sa->usage);
		}
		enumerator->destroy(enumerator);

		quota_invoke(ike_sa, QUOTA_STOP, entry);

		destroy_entry(entry);
	}
}

METHOD(listener_t, alert, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa, alert_t alert,
	va_list args)
{
	terminate_cause_t cause;
	quota_accounting_entry_t *entry;

	switch (alert)
	{
		case ALERT_IKE_SA_EXPIRED:
			cause = ACCT_CAUSE_SESSION_TIMEOUT;
			break;
		case ALERT_RETRANSMIT_SEND_TIMEOUT:
			cause = ACCT_CAUSE_LOST_SERVICE;
			break;
		default:
			return TRUE;
	}
	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions, ike_sa->get_id(ike_sa));
	if (entry)
	{
		entry->cause = cause;
	}
	this->mutex->unlock(this->mutex);
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa, bool up)
{
	if (!up)
	{
		enumerator_t *enumerator;
		child_sa_t *child_sa;

		/* update usage for all children just before sending stop */
		enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
		while (enumerator->enumerate(enumerator, &child_sa))
		{
			update_usage(this, ike_sa, child_sa);
		}
		enumerator->destroy(enumerator);

		do_stop(this, ike_sa);
	}
	return TRUE;
}

METHOD(listener_t, message_hook, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	/* start accounting here, virtual IP now is set */
	if (plain && ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		!incoming && !message->get_request(message))
	{
		if (ike_sa->get_version(ike_sa) == IKEV2 &&
			message->get_exchange_type(message) == IKE_AUTH)
		{
			do_start(this, ike_sa);
		}
	}
	return TRUE;
}

METHOD(listener_t, assign_vips, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa, bool assign)
{
	/* start accounting as soon as the virtual IP is set */
	if (assign && ike_sa->get_version(ike_sa) == IKEV1)
	{
		do_start(this, ike_sa);
	}
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
		private_quota_accounting_t *this, ike_sa_t *old, ike_sa_t *new)
{
	quota_accounting_entry_t *entry;

	this->mutex->lock(this->mutex);
	entry = this->sessions->remove(this->sessions, old->get_id(old));
	if (entry)
	{
		/* update IKE_SA identifier */
		entry->id->destroy(entry->id);
		entry->id = new->get_id(new);
		entry->id = entry->id->clone(entry->id);
		/* fire new update job, old gets invalid */
		schedule_update(this, entry);

		cleanup_sas(this, new, entry);

		entry = this->sessions->put(this->sessions, entry->id, entry);
		if (entry)
		{
			destroy_entry(entry);
		}
	}
	this->mutex->unlock(this->mutex);

	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa,
	child_sa_t *old, child_sa_t *new)
{
	quota_accounting_entry_t *entry;

	update_usage(this, ike_sa, old);
	this->mutex->lock(this->mutex);
	entry = this->sessions->get(this->sessions, ike_sa->get_id(ike_sa));
	if (entry)
	{
		cleanup_sas(this, ike_sa, entry);
	}
	this->mutex->unlock(this->mutex);
	return TRUE;
}

METHOD(listener_t, children_migrate, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa, ike_sa_id_t *new,
	u_int32_t unique)
{
	enumerator_t *enumerator;
	sa_entry_t *sa, *sa_new, *cached;
	quota_accounting_entry_t *entry_old, *entry_new;
	array_t *stats;

	if (!new)
	{
		return TRUE;
	}
	stats = collect_stats(ike_sa, NULL);
	this->mutex->lock(this->mutex);
	entry_old = this->sessions->get(this->sessions, ike_sa->get_id(ike_sa));
	if (entry_old)
	{
		entry_new = get_or_create_entry(this, new, unique);
		enumerator = array_create_enumerator(stats);
		while (enumerator->enumerate(enumerator, &sa))
		{
			/* if the SA was already rekeyed/cached we cache it too on the new
			 * SA to track it properly until it's finally gone */
			if (array_bsearch(entry_old->cached, sa, sa_find, &cached) != -1)
			{
				sa_new = clone_sa(sa);
				array_insert_create(&entry_new->cached, ARRAY_TAIL, sa_new);
				array_sort(entry_new->cached, sa_sort, NULL);
			}
			/* if the SA was used, we store it to compensate on the new SA */
			if (sa->usage.bytes.sent || sa->usage.bytes.received ||
				sa->usage.packets.sent || sa->usage.packets.received)
			{
				sa_new = clone_sa(sa);
				array_insert_create(&entry_new->migrated, ARRAY_TAIL, sa_new);
				array_sort(entry_new->migrated, sa_sort, NULL);
				/* store/update latest stats on old SA to report in Stop */
				update_sa(entry_old, sa->id, sa->usage);
			}
		}
		enumerator->destroy(enumerator);
	}
	this->mutex->unlock(this->mutex);
	array_destroy_function(stats, (void*)free, NULL);
	return TRUE;
}

METHOD(listener_t, child_updown, bool,
		private_quota_accounting_t *this, ike_sa_t *ike_sa,
	child_sa_t *child_sa, bool up)
{
	if (!up && ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		update_usage(this, ike_sa, child_sa);
	}
	return TRUE;
}

METHOD(quota_accounting_t, destroy, void,
		private_quota_accounting_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->public.listener);
	singleton = NULL;
	this->mutex->destroy(this->mutex);
	this->sessions->destroy(this->sessions);
	free(this);
}

/**
 * See header
 */
quota_accounting_t *quota_accounting_create()
{
	private_quota_accounting_t *this;

	INIT(this,
		.public = {
			.listener = {
				.alert = _alert,
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
				.message = _message_hook,
				.assign_vips = _assign_vips,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
				.children_migrate = _children_migrate,
			},
			.destroy = _destroy,
		},
		.sessions = hashtable_create((hashtable_hash_t)hash, (hashtable_equals_t)equals, 32),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.acct_req_vip = lib->settings->get_bool(
				lib->settings,
				"%s.plugins.quota.accounting_requires_vip",
				FALSE, lib->ns),
	);
	singleton = this;
	charon->bus->add_listener(charon->bus, &this->public.listener);
	return &this->public;
}

