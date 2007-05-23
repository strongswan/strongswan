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

typedef struct active_listener_t active_listener_t;

/**
 * information for a active listener
 */
struct active_listener_t {
	
	/**
	 * associated thread
	 */
	pthread_t id;
	
	/**
	 * condvar to wait for a signal
	 */
	pthread_cond_t cond;
	
	/**
	 * state of the thread
	 */
	enum {
		/** not registered, do not wait for thread */
		UNREGISTERED,
		/** registered, if a signal occurs, wait until it is LISTENING */
		REGISTERED,
		/** listening, deliver signal */
		LISTENING,
	} state;
	
	/**
	 * currently processed signals type
	 */
	signal_t signal;
	
	/**
	 * verbosity level of the signal
	 */
	level_t level;
	
	/**
	 * current processed signals thread number
	 */
	int thread;
	
	/**
	 * currently processed signals ike_sa
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * currently processed signals format string
	 */
	char *format;
	
	/**
	 * currently processed signals format varargs
	 */
	va_list args;
	
};

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
	 * List of registered listeners implementing the bus_t interface
	 */
	linked_list_t *listeners;
	
	/**
	 * List of active listeners with listener_state TRUE
	 */
	linked_list_t *active_listeners;
	
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

/**
 * Get a unique thread number for a calling thread. Since
 * pthread_self returns large and ugly numbers, use this function
 * for logging; these numbers are incremental starting at 1
 */
static int get_thread_number(private_bus_t *this)
{
	static long current_num = 0;
	static long stored_num;
	
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
	this->listeners->insert_last(this->listeners, listener);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of bus_t.remove_listener.
 */
static void remove_listener(private_bus_t *this, bus_listener_t *listener)
{
	iterator_t *iterator;
	bus_listener_t *current;

	pthread_mutex_lock(&this->mutex);
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current == listener)
		{
			iterator->remove(iterator);
			break;
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Get the listener object for the calling thread
 */
static active_listener_t *get_active_listener(private_bus_t *this)
{
	active_listener_t *current, *found = NULL;
	iterator_t *iterator;
	
	/* if the thread was here once before, we have a active_listener record */
	iterator = this->active_listeners->create_iterator(this->active_listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->id == pthread_self())
		{
			found = current;
			break;
		}
	}
	iterator->destroy(iterator);
	
	if (found == NULL)
	{
		/* create a new object for a never-seen thread */
		found = malloc_thing(active_listener_t);
		found->id = pthread_self();
		pthread_cond_init(&found->cond, NULL);
		this->active_listeners->insert_last(this->active_listeners, found);
	}
	
	return found;
}

typedef struct cancel_info_t cancel_info_t;

/**
 * cancellation info to cancel a listening operation cleanly
 */
struct cancel_info_t {
	/**
	 * mutex to unlock on cancellation
	 */
	pthread_mutex_t *mutex;
	
	/**
	 * listener to unregister
	 */
	active_listener_t *listener;
};

/**
 * disable a listener to cleanly clean up
 */
static void unregister(cancel_info_t *info)
{
	info->listener->state = UNREGISTERED;
	pthread_mutex_unlock(info->mutex);
}

/**
 * Implementation of bus_t.listen.
 */
static signal_t listen_(private_bus_t *this, level_t *level, int *thread,
						ike_sa_t **ike_sa, char** format, va_list* args)
{
	active_listener_t *listener;
	int oldstate;
	cancel_info_t info;
	
	pthread_mutex_lock(&this->mutex);
	listener = get_active_listener(this);
	/* go "listening", say hello to a thread which have a signal for us */
	listener->state = LISTENING;
	pthread_cond_broadcast(&listener->cond);
	/* wait until it has us delivered a signal, and go back to "registered".
	 * we allow cancellation here, but must cleanly disable the listener. */
	info.mutex = &this->mutex;
	info.listener = listener;
	pthread_cleanup_push((void*)unregister, &info);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	pthread_cond_wait(&listener->cond, &this->mutex);
	pthread_setcancelstate(oldstate, NULL);
	pthread_cleanup_pop(0);
	
	pthread_mutex_unlock(&this->mutex);
	
	/* return signal values */
	*level  = listener->level;
	*thread = listener->thread;
	*ike_sa = listener->ike_sa;
	*format = listener->format;
	va_copy(*args, listener->args);
	va_end(listener->args);
	
	return listener->signal;
}

/**
 * Implementation of bus_t.set_listen_state.
 */
static void set_listen_state(private_bus_t *this, bool active)
{
	active_listener_t *listener;
	
	pthread_mutex_lock(&this->mutex);
	
	listener = get_active_listener(this);
	if (active)
	{
		listener->state = REGISTERED;
	}
	else
	{
		listener->state = UNREGISTERED;
		/* say hello to signal emitter; we are finished processing the signal */
		pthread_cond_signal(&listener->cond);
	}
	
	pthread_mutex_unlock(&this->mutex);
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
	bus_listener_t *listener;
	active_listener_t *active_listener;
	ike_sa_t *ike_sa;
	long thread;
	
	ike_sa = pthread_getspecific(this->thread_sa);
	thread = get_thread_number(this);
	
	pthread_mutex_lock(&this->mutex);
	
	/* do the job for all passive bus_listeners */
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&listener))
	{
		va_list args_copy;
		va_copy(args_copy, args);
		if (!listener->signal(listener, signal, level, thread, 
							  ike_sa, format, args_copy))
		{
			/* unregister listener if requested */
			iterator->remove(iterator);
		}
		va_end(args_copy);
	}
	iterator->destroy(iterator);
	
	/* wake up all active listeners */
	iterator = this->active_listeners->create_iterator(this->active_listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&active_listener))
	{
		/* wait until all threads are registered. But if the thread raising
		 * the signal is the same as the one that listens, we skip it.
		 * Otherwise we would deadlock. */
		while (active_listener->id != pthread_self() &&
			   active_listener->state == REGISTERED)
		{
			pthread_cond_wait(&active_listener->cond, &this->mutex);
		}
		/* if thread is listening now, give it the signal to process */
		if (active_listener->state == LISTENING)
		{
			active_listener->level = level;
			active_listener->thread = thread;
			active_listener->ike_sa = ike_sa;
			active_listener->signal = signal;
			active_listener->format = format;
			va_copy(active_listener->args, args);
			active_listener->state = REGISTERED;
			pthread_cond_signal(&active_listener->cond);
		}
	}
	
	/* we must wait now until all are not in state REGISTERED,
	 * as they may still use our arguments */
	iterator->reset(iterator);
	while (iterator->iterate(iterator, (void**)&active_listener))
	{
		/* do not wait for ourself, it won't happen (see above) */
		while (active_listener->id != pthread_self() &&
			   active_listener->state == REGISTERED)
		{
			pthread_cond_wait(&active_listener->cond, &this->mutex);
		}
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
	this->active_listeners->destroy_function(this->active_listeners, free);
	this->listeners->destroy(this->listeners);
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
	this->public.listen = (signal_t(*)(bus_t*,level_t*,int*,ike_sa_t**,char**,va_list*))listen_;
	this->public.set_listen_state = (void(*)(bus_t*,bool))set_listen_state;
	this->public.set_sa = (void(*)(bus_t*,ike_sa_t*))set_sa;
	this->public.signal = (void(*)(bus_t*,signal_t,level_t,char*,...))signal_;
	this->public.vsignal = (void(*)(bus_t*,signal_t,level_t,char*,va_list))vsignal;
	this->public.destroy = (void(*)(bus_t*)) destroy;
	
	this->listeners = linked_list_create();
	this->active_listeners = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	pthread_key_create(&this->thread_id, NULL);
	pthread_key_create(&this->thread_sa, NULL);
	
	return &(this->public);
}
