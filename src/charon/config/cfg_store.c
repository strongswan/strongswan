/**
 * @file cfg_store.c
 * 
 * @brief Implementation of cfg_store_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include <pthread.h>

#include "cfg_store.h"

#include <library.h>
#include <utils/linked_list.h>


typedef struct private_cfg_store_t private_cfg_store_t;

/**
 * Private data of an cfg_store_t object.
 */
struct private_cfg_store_t {

	/**
	 * Public part of cfg_store_t object.
	 */
	cfg_store_t public;
	
	/**
	 * list of registered backends
	 */
	linked_list_t *backends;
	
	/**
	 * mutex to lock backend list
	 */
	pthread_mutex_t mutex;
};

/**
 * implements cfg_store_t.get_ike.
 */
static ike_cfg_t *get_ike_cfg(private_cfg_store_t *this, 
							  host_t *my_host, host_t *other_host)
{
	backend_t *backend;
	ike_cfg_t *config = NULL;
	iterator_t *iterator = this->backends->create_iterator_locked(
												this->backends, &this->mutex);
	while (config == NULL && iterator->iterate(iterator, (void**)&backend))
	{
		config = backend->get_ike_cfg(backend, my_host, other_host);
	}
	iterator->destroy(iterator);
	return config;
}

/**
 * implements cfg_store_t.get_peer.
 */			
static peer_cfg_t *get_peer_cfg(private_cfg_store_t *this, 
								identification_t *my_id,
								identification_t *other_id)
{
	backend_t *backend;
	peer_cfg_t *config = NULL;
	iterator_t *iterator = this->backends->create_iterator_locked(
												this->backends, &this->mutex);
	while (config == NULL && iterator->iterate(iterator, (void**)&backend))
	{
		config = backend->get_peer_cfg(backend, my_id, other_id);
	}
	iterator->destroy(iterator);
	return config;
}

/**
 * implements cfg_store_t.register_backend.
 */			
static void register_backend(private_cfg_store_t *this, backend_t *backend)
{
	pthread_mutex_lock(&this->mutex);
	this->backends->insert_last(this->backends, backend);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * implements cfg_store_t.unregister_backend.
 */			
static void unregister_backend(private_cfg_store_t *this, backend_t *backend)
{
	backend_t *current;
	iterator_t *iterator = this->backends->create_iterator_locked(
												this->backends, &this->mutex);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (backend == current)
		{
			iterator->remove(iterator);
			break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of cfg_store_t.destroy.
 */
static void destroy(private_cfg_store_t *this)
{
	this->backends->destroy(this->backends);
	free(this);
}

/*
 * Described in header-file
 */
cfg_store_t *cfg_store_create()
{
	private_cfg_store_t *this = malloc_thing(private_cfg_store_t);
	
	this->public.get_ike_cfg = (ike_cfg_t*(*)(cfg_store_t*, host_t *, host_t *))get_ike_cfg;
	this->public.get_peer_cfg = (peer_cfg_t*(*)(cfg_store_t*, identification_t *, identification_t *))get_peer_cfg;
	this->public.register_backend = (void(*)(cfg_store_t*, backend_t *))register_backend;
	this->public.unregister_backend = (void(*)(cfg_store_t*, backend_t *))unregister_backend;
	this->public.destroy = (void(*)(cfg_store_t*))destroy;
	
	this->backends = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	
	return &this->public;
}
