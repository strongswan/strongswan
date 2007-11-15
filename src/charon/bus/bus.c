/**
 * @file bus.c
 *
 * @brief Implementation of bus_t.
 *
 */

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

#include <pthread.h>

#include <daemon.h>

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
	 * mutex to synchronize active listeners
	 */
	pthread_mutex_t mutex;
	
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
	 * condvar where active listeners wait
	 */
	pthread_cond_t cond;
};

/**
 * create a listener entry
 */
static entry_t *entry_create(bus_listener_t *listener, bool blocker)
{
	entry_t *this = malloc_thing(entry_t);
	
	this->listener = listener;
	this->blocker = blocker;
	pthread_cond_init(&this->cond, NULL);
	
	return this;
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
	pthread_mutex_lock(&this->mutex);
	this->listeners->insert_last(this->listeners, entry_create(listener, FALSE));
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of bus_t.remove_listener.
 */
static void remove_listener(private_bus_t *this, bus_listener_t *listener)
{
	iterator_t *iterator;
	entry_t *entry;

	pthread_mutex_lock(&this->mutex);
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		if (entry->listener == listener)
		{
			iterator->remove(iterator);
			free(entry);
			break;
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of bus_t.listen.
 */
static void listen_(private_bus_t *this, bus_listener_t *listener, job_t *job)
{
	entry_t *entry;
	int old;
	
	entry = entry_create(listener, TRUE);

	pthread_mutex_lock(&this->mutex);
	this->listeners->insert_last(this->listeners, entry);
	charon->processor->queue_job(charon->processor, job);
	pthread_cleanup_push((void*)pthread_mutex_unlock, &this->mutex);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	while (entry->blocker)
	{
		pthread_cond_wait(&entry->cond, &this->mutex);
	}
	pthread_setcancelstate(old, NULL);
	pthread_cleanup_pop(TRUE);
	free(entry);
}

/**
 * Implementation of bus_t.set_sa.
 */
static void set_sa(private_bus_t *this, ike_sa_t *ike_sa)
{
	pthread_setspecific(this->thread_sa, ike_sa);
}

/**
 * Implementation of bus_t.vsignal.
 */
static void vsignal(private_bus_t *this, signal_t signal, level_t level,
					char* format, va_list args)
{
	iterator_t *iterator;
	entry_t *entry;
	ike_sa_t *ike_sa;
	long thread;
	
	pthread_mutex_lock(&this->mutex);
	ike_sa = pthread_getspecific(this->thread_sa);
	thread = get_thread_number(this);
	
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		va_list args_copy;
		va_copy(args_copy, args);
		if (!entry->listener->signal(entry->listener, signal, level, thread, 
									 ike_sa, format, args_copy))
		{
			iterator->remove(iterator);
			if (entry->blocker)
			{
				entry->blocker = FALSE;
				pthread_cond_signal(&entry->cond);
			}
			else
			{
				free(entry);
			}
		}
		va_end(args_copy);
	}
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of bus_t.signal.
 */
static void signal_(private_bus_t *this, signal_t signal, level_t level, 
					char* format, ...)
{
	va_list args;
	
	va_start(args, format);
	vsignal(this, signal, level, format, args);
	va_end(args);
}

/**
 * Implementation of bus_t.destroy.
 */
static void destroy(private_bus_t *this)
{
	this->listeners->destroy_function(this->listeners, free);
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
	this->public.signal = (void(*)(bus_t*,signal_t,level_t,char*,...))signal_;
	this->public.vsignal = (void(*)(bus_t*,signal_t,level_t,char*,va_list))vsignal;
	this->public.destroy = (void(*)(bus_t*)) destroy;
	
	this->listeners = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	pthread_key_create(&this->thread_id, NULL);
	pthread_key_create(&this->thread_sa, NULL);
	
	return &this->public;
}

