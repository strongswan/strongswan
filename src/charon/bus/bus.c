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
	static int current_num = 0, stored_num;
	
	stored_num = (int)pthread_getspecific(this->thread_id);
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
	this->listeners->insert_last(this->listeners, (void*)listener);
}

/**
 * Implementation of bus_t.set_sa.
 */
static void set_sa(private_bus_t *this, ike_sa_t *ike_sa)
{
	pthread_setspecific(this->thread_sa, ike_sa);
}

/**
 * Implementation of bus_t.signal.
 */
static void signal_(private_bus_t *this, signal_t signal, level_t condition,
					char* format, ...)
{
	iterator_t *iterator;
	bus_listener_t *listener;
	va_list args;
	ike_sa_t *ike_sa;
	int thread;
	
	ike_sa = pthread_getspecific(this->thread_sa);
	thread = get_thread_number(this);
	va_start(args, format);
	
	iterator = this->listeners->create_iterator(this->listeners, TRUE);
	while (iterator->iterate(iterator, (void**)&listener))
	{
		listener->signal(listener, thread, ike_sa,
						 signal, condition, format, args);
	}
	iterator->destroy(iterator);
	va_end(args);
}

/**
 * Implementation of bus_t.destroy.
 */
static void destroy(private_bus_t *this)
{
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
	this->public.set_sa = (void(*)(bus_t*,ike_sa_t*))set_sa;
	this->public.signal = (void(*)(bus_t*,signal_t,level_t,char*,...))signal_;
	this->public.destroy = (void(*)(bus_t*)) destroy;
	
	this->listeners = linked_list_create();
	pthread_key_create(&this->thread_id, NULL);
	pthread_key_create(&this->thread_sa, NULL);
	
	return &(this->public);
}
