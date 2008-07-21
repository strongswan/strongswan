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
 *
 * $Id$
 */

#include "bus.h"

#include <pthread.h>

#include <daemon.h>
#include <utils/mutex.h>

ENUM(signal_names, SIG_ANY, SIG_MAX,
	/** should not get printed */
	"SIG_ANY",
	/** debugging message types */
	"DMN",
	"MGR",
	"IKE",
	"CHD",
	"JOB",
	"CFG",
	"KNL",
	"NET",
	"ENC",
	"LIB",
	/** should not get printed */
	"SIG_DBG_MAX",
	/** all level0 signals are AUDIT signals */
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	"AUD", "AUD", "AUD",
	/** should not get printed */
	"SIG_MAX",
);

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
	 * Thread local storage for a unique, simple thread ID
	 */
	pthread_key_t thread_id;
	
	/**
	 * Thread local storage the threads IKE_SA
	 */
	pthread_key_t thread_sa;
};

typedef struct entry_t entry_t;

/**
 * a listener entry, either active or passive
 */
struct entry_t {

	/**
	 * registered listener interface
	 */
	bus_listener_t *listener;
	
	/**
	 * is this a active listen() call with a blocking thread
	 */
	bool blocker;
	
	/**
	 * are we currently calling this listener
	 */
	bool calling;
	
	/**
	 * condvar where active listeners wait
	 */
	condvar_t *condvar;
};

/**
 * create a listener entry
 */
static entry_t *entry_create(bus_listener_t *listener, bool blocker)
{
	entry_t *this = malloc_thing(entry_t);
	
	this->listener = listener;
	this->blocker = blocker;
	this->calling = FALSE;
	this->condvar = condvar_create(CONDVAR_DEFAULT);
	
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

/**
 * Get a unique thread number for a calling thread. Since
 * pthread_self returns large and ugly numbers, use this function
 * for logging; these numbers are incremental starting at 1
 */
static int get_thread_number(private_bus_t *this)
{
	static long current_num = 0;
	long stored_num;
	
	stored_num = (long)pthread_getspecific(this->thread_id);
	if (stored_num == 0)
	{	/* first call of current thread */
		pthread_setspecific(this->thread_id, (void*)++current_num);
		return current_num;
	}
	else
	{
		return stored_num;
	}
}

/**
 * Implementation of bus_t.add_listener.
 */
static void add_listener(private_bus_t *this, bus_listener_t *listener)
{
	this->mutex->lock(this->mutex);
	this->listeners->insert_last(this->listeners, entry_create(listener, FALSE));
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of bus_t.remove_listener.
 */
static void remove_listener(private_bus_t *this, bus_listener_t *listener)
{
	iterator_t *iterator;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		if (entry->listener == listener)
		{
			iterator->remove(iterator);
			entry_destroy(entry);
			break;
		}
	}
	iterator->destroy(iterator);
	this->mutex->unlock(this->mutex);
}

typedef struct cleanup_data_t cleanup_data_t;

/**
 * data to remove a listener using pthread_cleanup handler
 */
struct cleanup_data_t {
	/** bus instance */
	private_bus_t *this;
	/** listener entry */
	entry_t *entry;
};

/**
 * pthread_cleanup handler to remove a listener
 */
static void listener_cleanup(cleanup_data_t *data)
{
	iterator_t *iterator;
	entry_t *entry;

	iterator = data->this->listeners->create_iterator(data->this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		if (entry == data->entry)
		{
			iterator->remove(iterator);
			entry_destroy(entry);
			break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of bus_t.listen.
 */
static void listen_(private_bus_t *this, bus_listener_t *listener, job_t *job)
{
	int old;
	cleanup_data_t data;
	
	data.this = this;
	data.entry = entry_create(listener, TRUE);

	this->mutex->lock(this->mutex);
	this->listeners->insert_last(this->listeners, data.entry);
	charon->processor->queue_job(charon->processor, job);
	pthread_cleanup_push((void*)this->mutex->unlock, this->mutex);
	pthread_cleanup_push((void*)listener_cleanup, &data);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	while (data.entry->blocker)
	{
		data.entry->condvar->wait(data.entry->condvar, this->mutex);
	}
	pthread_setcancelstate(old, NULL);
	pthread_cleanup_pop(FALSE);
	/* unlock mutex */
	pthread_cleanup_pop(TRUE);
	entry_destroy(data.entry);
}

/**
 * Implementation of bus_t.set_sa.
 */
static void set_sa(private_bus_t *this, ike_sa_t *ike_sa)
{
	pthread_setspecific(this->thread_sa, ike_sa);
}

/**
 * data associated to a signal, passed to callback
 */
typedef struct {
	/** associated IKE_SA */
	ike_sa_t *ike_sa;
	/** invoking thread */
	long thread;
	/** signal type */
	signal_t signal;
	/** signal level */
	level_t level;
	/** signal specific user data */
	void *user;
	/** format string */
	char *format;
	/** argument list */
	va_list args;
} signal_data_t;

/**
 * listener invocation as a list remove callback
 */
static bool signal_cb(entry_t *entry, signal_data_t *data)
{
	va_list args;

	if (entry->calling)
	{	/* avoid recursive calls */
		return FALSE;
	}
	entry->calling = TRUE;
	va_copy(args, data->args);
	if (!entry->listener->signal(entry->listener, data->signal, data->level,
					data->thread, data->ike_sa, data->user, data->format, args))
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
		va_end(args);
		entry->calling = FALSE;
		return TRUE;
	}
	va_end(args);
	entry->calling = FALSE;
	return FALSE;
}

/**
 * Implementation of bus_t.vsignal.
 */
static void vsignal(private_bus_t *this, signal_t signal, level_t level,
					void *user, char* format, va_list args)
{
	signal_data_t data;
	
	data.ike_sa = pthread_getspecific(this->thread_sa);
	data.thread = get_thread_number(this);
	data.signal = signal;
	data.level = level;
	data.user = user;
	data.format = format;
	va_copy(data.args, args);
	
	this->mutex->lock(this->mutex);
	/* we use the remove() method to invoke all listeners with small overhead */
	this->listeners->remove(this->listeners, &data, (void*)signal_cb);
	this->mutex->unlock(this->mutex);
	
	va_end(data.args);
}

/**
 * Implementation of bus_t.signal.
 */
static void signal_(private_bus_t *this, signal_t signal, level_t level, 
					void* data, char* format, ...)
{
	va_list args;
	
	va_start(args, format);
	vsignal(this, signal, level, data, format, args);
	va_end(args);
}

/**
 * Implementation of bus_t.destroy.
 */
static void destroy(private_bus_t *this)
{
	this->mutex->destroy(this->mutex);
	this->listeners->destroy_function(this->listeners, (void*)entry_destroy);
	free(this);
}

/*
 * Described in header.
 */
bus_t *bus_create()
{
	private_bus_t *this = malloc_thing(private_bus_t);
	
	this->public.add_listener = (void(*)(bus_t*,bus_listener_t*))add_listener;
	this->public.remove_listener = (void(*)(bus_t*,bus_listener_t*))remove_listener;
	this->public.listen = (void(*)(bus_t*, bus_listener_t *listener, job_t *job))listen_;
	this->public.set_sa = (void(*)(bus_t*,ike_sa_t*))set_sa;
	this->public.signal = (void(*)(bus_t*,signal_t,level_t,void*,char*,...))signal_;
	this->public.vsignal = (void(*)(bus_t*,signal_t,level_t,void*,char*,va_list))vsignal;
	this->public.destroy = (void(*)(bus_t*)) destroy;
	
	this->listeners = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	pthread_key_create(&this->thread_id, NULL);
	pthread_key_create(&this->thread_sa, NULL);
	
	return &this->public;
}

