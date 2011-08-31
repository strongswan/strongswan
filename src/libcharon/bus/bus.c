/*
 * Copyright (C) 2006 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "bus.h"

#include <stdint.h>

#include <threading/thread.h>
#include <threading/thread_value.h>
#include <threading/condvar.h>
#include <threading/mutex.h>

typedef struct private_bus_t private_bus_t;

/**
 * Private data of a bus_t object.
 */
struct private_bus_t {
	/**
	 * Public part of a bus_t object.
	 */
	bus_t public;

	/**
	 * List of registered listeners as entry_t's
	 */
	linked_list_t *listeners;

	/**
	 * mutex to synchronize active listeners, recursively
	 */
	mutex_t *mutex;

	/**
	 * Thread local storage the threads IKE_SA
	 */
	thread_value_t *thread_sa;
};

typedef struct entry_t entry_t;

/**
 * a listener entry, either active or passive
 */
struct entry_t {

	/**
	 * registered listener interface
	 */
	listener_t *listener;

	/**
	 * is this a active listen() call with a blocking thread
	 */
	bool blocker;

	/**
	 * are we currently calling this listener
	 */
	int calling;

	/**
	 * condvar where active listeners wait
	 */
	condvar_t *condvar;
};

/**
 * create a listener entry
 */
static entry_t *entry_create(listener_t *listener, bool blocker)
{
	entry_t *this = malloc_thing(entry_t);

	this->listener = listener;
	this->blocker = blocker;
	this->calling = 0;
	this->condvar = condvar_create(CONDVAR_TYPE_DEFAULT);

	return this;
}

/**
 * destroy an entry_t
 */
static void entry_destroy(entry_t *entry)
{
	entry->condvar->destroy(entry->condvar);
	free(entry);
}

METHOD(bus_t, add_listener, void,
	private_bus_t *this, listener_t *listener)
{
	this->mutex->lock(this->mutex);
	this->listeners->insert_last(this->listeners, entry_create(listener, FALSE));
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, remove_listener, void,
	private_bus_t *this, listener_t *listener)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->listener == listener)
		{
			this->listeners->remove_at(this->listeners, enumerator);
			entry_destroy(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

typedef struct cleanup_data_t cleanup_data_t;

/**
 * data to remove a listener using thread_cleanup_t handler
 */
struct cleanup_data_t {
	/** bus instance */
	private_bus_t *this;
	/** listener entry */
	entry_t *entry;
};

/**
 * thread_cleanup_t handler to remove a listener
 */
static void listener_cleanup(cleanup_data_t *data)
{
	data->this->listeners->remove(data->this->listeners, data->entry, NULL);
	entry_destroy(data->entry);
}

METHOD(bus_t, listen_, bool,
	private_bus_t *this, listener_t *listener, job_t *job, u_int timeout)
{
	bool old, timed_out = FALSE;
	cleanup_data_t data;
	timeval_t tv, add;

	if (timeout)
	{
		add.tv_sec = timeout / 1000;
		add.tv_usec = (timeout - (add.tv_sec * 1000)) * 1000;
		time_monotonic(&tv);
		timeradd(&tv, &add, &tv);
	}

	data.this = this;
	data.entry = entry_create(listener, TRUE);

	this->mutex->lock(this->mutex);
	this->listeners->insert_last(this->listeners, data.entry);
	lib->processor->queue_job(lib->processor, job);
	thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
	thread_cleanup_push((thread_cleanup_t)listener_cleanup, &data);
	old = thread_cancelability(TRUE);
	while (data.entry->blocker)
	{
		if (timeout)
		{
			if (data.entry->condvar->timed_wait_abs(data.entry->condvar,
												    this->mutex, tv))
			{
				this->listeners->remove(this->listeners, data.entry, NULL);
				timed_out = TRUE;
				break;
			}
		}
		else
		{
			data.entry->condvar->wait(data.entry->condvar, this->mutex);
		}
	}
	thread_cancelability(old);
	thread_cleanup_pop(FALSE);
	/* unlock mutex */
	thread_cleanup_pop(TRUE);
	entry_destroy(data.entry);
	return timed_out;
}

METHOD(bus_t, set_sa, void,
	private_bus_t *this, ike_sa_t *ike_sa)
{
	this->thread_sa->set(this->thread_sa, ike_sa);
}

METHOD(bus_t, get_sa, ike_sa_t*,
	private_bus_t *this)
{
	return this->thread_sa->get(this->thread_sa);
}

/**
 * data associated to a signal, passed to callback
 */
typedef struct {
	/** associated IKE_SA */
	ike_sa_t *ike_sa;
	/** invoking thread */
	long thread;
	/** debug group */
	debug_t group;
	/** debug level */
	level_t level;
	/** format string */
	char *format;
	/** argument list */
	va_list args;
} log_data_t;

/**
 * listener->log() invocation as a list remove callback
 */
static bool log_cb(entry_t *entry, log_data_t *data)
{
	va_list args;

	if (entry->calling || !entry->listener->log)
	{	/* avoid recursive calls */
		return FALSE;
	}
	entry->calling++;
	va_copy(args, data->args);
	if (!entry->listener->log(entry->listener, data->group, data->level,
							  data->thread, data->ike_sa, data->format, args))
	{
		if (entry->blocker)
		{
			entry->blocker = FALSE;
			entry->condvar->signal(entry->condvar);
			entry->calling--;
		}
		else
		{
			entry_destroy(entry);
		}
		va_end(args);
		return TRUE;
	}
	va_end(args);
	entry->calling--;
	return FALSE;
}

METHOD(bus_t, vlog, void,
	private_bus_t *this, debug_t group, level_t level,
	char* format, va_list args)
{
	log_data_t data;

	data.ike_sa = this->thread_sa->get(this->thread_sa);
	data.thread = thread_current_id();
	data.group = group;
	data.level = level;
	data.format = format;
	va_copy(data.args, args);

	this->mutex->lock(this->mutex);
	/* We use the remove() method to invoke all listeners. This is cheap and
	 * does not require an allocation for this performance critical function. */
	this->listeners->remove(this->listeners, &data, (void*)log_cb);
	this->mutex->unlock(this->mutex);

	va_end(data.args);
}

METHOD(bus_t, log_, void,
	private_bus_t *this, debug_t group, level_t level, char* format, ...)
{
	va_list args;

	va_start(args, format);
	vlog(this, group, level, format, args);
	va_end(args);
}

/**
 * unregister a listener
 */
static void unregister_listener(private_bus_t *this, entry_t *entry,
								enumerator_t *enumerator)
{
	if (entry->blocker)
	{
		entry->blocker = FALSE;
		entry->condvar->signal(entry->condvar);
	}
	else
	{
		entry_destroy(entry);
	}
	this->listeners->remove_at(this->listeners, enumerator);
}

METHOD(bus_t, alert, void,
	private_bus_t *this, alert_t alert, ...)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	va_list args;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->alert)
		{
			continue;
		}
		entry->calling++;
		va_start(args, alert);
		keep = entry->listener->alert(entry->listener, ike_sa, alert, args);
		va_end(args);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, ike_state_change, void,
	private_bus_t *this, ike_sa_t *ike_sa, ike_sa_state_t state)
{
	enumerator_t *enumerator;
	entry_t *entry;
	bool keep;

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->ike_state_change)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->ike_state_change(entry->listener, ike_sa, state);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, child_state_change, void,
	private_bus_t *this, child_sa_t *child_sa, child_sa_state_t state)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->child_state_change)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->child_state_change(entry->listener, ike_sa,
												   child_sa, state);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, message, void,
	private_bus_t *this, message_t *message, bool incoming)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->message)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->message(entry->listener, ike_sa,
										message, incoming);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, ike_keys, void,
	private_bus_t *this, ike_sa_t *ike_sa, diffie_hellman_t *dh,
	chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey)
{
	enumerator_t *enumerator;
	entry_t *entry;
	bool keep;

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->ike_keys)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->ike_keys(entry->listener, ike_sa, dh,
										 nonce_i, nonce_r, rekey);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, child_keys, void,
	private_bus_t *this, child_sa_t *child_sa, bool initiator,
	diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->child_keys)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->child_keys(entry->listener, ike_sa, child_sa,
										   initiator, dh, nonce_i, nonce_r);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, child_updown, void,
	private_bus_t *this, child_sa_t *child_sa, bool up)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->child_updown)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->child_updown(entry->listener,
											 ike_sa, child_sa, up);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, child_rekey, void,
	private_bus_t *this, child_sa_t *old, child_sa_t *new)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->child_rekey)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->child_rekey(entry->listener, ike_sa, old, new);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, ike_updown, void,
	private_bus_t *this, ike_sa_t *ike_sa, bool up)
{
	enumerator_t *enumerator;
	entry_t *entry;
	bool keep;

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->ike_updown)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->ike_updown(entry->listener, ike_sa, up);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	/* a down event for IKE_SA implicitly downs all CHILD_SAs */
	if (!up)
	{
		enumerator_t *enumerator;
		child_sa_t *child_sa;

		enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
		while (enumerator->enumerate(enumerator, (void**)&child_sa))
		{
			child_updown(this, child_sa, FALSE);
		}
		enumerator->destroy(enumerator);
	}
}

METHOD(bus_t, ike_rekey, void,
	private_bus_t *this, ike_sa_t *old, ike_sa_t *new)
{
	enumerator_t *enumerator;
	entry_t *entry;
	bool keep;

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->ike_rekey)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->ike_rekey(entry->listener, old, new);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, authorize, bool,
	private_bus_t *this, bool final)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep, success = TRUE;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->authorize)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->authorize(entry->listener, ike_sa,
										  final, &success);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
		if (!success)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return success;
}

METHOD(bus_t, narrow, void,
	private_bus_t *this, child_sa_t *child_sa, narrow_hook_t type,
	linked_list_t *local, linked_list_t *remote)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	entry_t *entry;
	bool keep;

	ike_sa = this->thread_sa->get(this->thread_sa);

	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->calling || !entry->listener->narrow)
		{
			continue;
		}
		entry->calling++;
		keep = entry->listener->narrow(entry->listener, ike_sa, child_sa,
									   type, local, remote);
		entry->calling--;
		if (!keep)
		{
			unregister_listener(this, entry, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(bus_t, destroy, void,
	private_bus_t *this)
{
	this->thread_sa->destroy(this->thread_sa);
	this->mutex->destroy(this->mutex);
	this->listeners->destroy_function(this->listeners, (void*)entry_destroy);
	free(this);
}

/*
 * Described in header.
 */
bus_t *bus_create()
{
	private_bus_t *this;

	INIT(this,
		.public = {
			.add_listener = _add_listener,
			.remove_listener = _remove_listener,
			.listen = _listen_,
			.set_sa = _set_sa,
			.get_sa = _get_sa,
			.log = _log_,
			.vlog = _vlog,
			.alert = _alert,
			.ike_state_change = _ike_state_change,
			.child_state_change = _child_state_change,
			.message = _message,
			.ike_keys = _ike_keys,
			.child_keys = _child_keys,
			.ike_updown = _ike_updown,
			.ike_rekey = _ike_rekey,
			.child_updown = _child_updown,
			.child_rekey = _child_rekey,
			.authorize = _authorize,
			.narrow = _narrow,
			.destroy = _destroy,
		},
		.listeners = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.thread_sa = thread_value_create(NULL),
	);

	return &this->public;
}

