/*
 * Copyright (C) 2008 Martin Willi
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

#include "attribute_manager.h"

#include <utils/linked_list.h>
#include <utils/mutex.h>

typedef struct private_attribute_manager_t private_attribute_manager_t;

/**
 * private data of attribute_manager
 */
struct private_attribute_manager_t {

	/**
	 * public functions
	 */
	attribute_manager_t public;
	
	/**
	 * list of registered providers
	 */
	linked_list_t *providers;
	
	/**
	 * mutex to lock provider list
	 */
	mutex_t *mutex;
};

/**
 * Implementation of attribute_manager_t.acquire_address.
 */
static host_t* acquire_address(private_attribute_manager_t *this,
							   char *pool, identification_t *id,
							   auth_info_t *auth, host_t *requested)
{
	enumerator_t *enumerator;
	attribute_provider_t *current;
	host_t *host = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &current))
	{
		host = current->acquire_address(current, pool, id, auth, requested);
		if (host)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	
	return host;
}

/**
 * Implementation of attribute_manager_t.release_address.
 */
static void release_address(private_attribute_manager_t *this,
							char *pool, host_t *address)
{
	enumerator_t *enumerator;
	attribute_provider_t *current;

	this->mutex->lock(this->mutex);
	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->release_address(current, pool, address))
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of attribute_manager_t.add_provider.
 */
static void add_provider(private_attribute_manager_t *this,
						 attribute_provider_t *provider)
{
	this->mutex->lock(this->mutex);
	this->providers->insert_last(this->providers, provider);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of attribute_manager_t.remove_provider.
 */
static void remove_provider(private_attribute_manager_t *this,
							attribute_provider_t *provider)
{
	this->mutex->lock(this->mutex);
	this->providers->remove(this->providers, provider, NULL);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of attribute_manager_t.destroy
 */
static void destroy(private_attribute_manager_t *this)
{
	this->providers->destroy(this->providers);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
attribute_manager_t *attribute_manager_create()
{
	private_attribute_manager_t *this = malloc_thing(private_attribute_manager_t);
	
	this->public.acquire_address = (host_t*(*)(attribute_manager_t*, char*, identification_t*,auth_info_t*,host_t*))acquire_address;
	this->public.release_address = (void(*)(attribute_manager_t*, char *, host_t*))release_address;
	this->public.add_provider = (void(*)(attribute_manager_t*, attribute_provider_t *provider))add_provider;
	this->public.remove_provider = (void(*)(attribute_manager_t*, attribute_provider_t *provider))remove_provider;
	this->public.destroy = (void(*)(attribute_manager_t*))destroy;
	
	this->providers = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	return &this->public;
}

