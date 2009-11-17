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
 */

#include "attribute_manager.h"

#include <debug.h>
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
	 * list of registered handlers
	 */
	linked_list_t *handlers;

	/**
	 * rwlock provider list
	 */
	rwlock_t *lock;
};

/**
 * Data to pass to enumerator filters
 */
typedef struct {
	/** server/peer identity */
	identification_t *id;
	/** requesting/assigned virtual IP */
	host_t *vip;
} enum_data_t;

/**
 * Implementation of attribute_manager_t.acquire_address.
 */
static host_t* acquire_address(private_attribute_manager_t *this,
							   char *pool, identification_t *id,
							   host_t *requested)
{
	enumerator_t *enumerator;
	attribute_provider_t *current;
	host_t *host = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &current))
	{
		host = current->acquire_address(current, pool, id, requested);
		if (host)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!host)
	{
		DBG1("acquiring address from pool '%s' failed", pool);
	}
	return host;
}

/**
 * Implementation of attribute_manager_t.release_address.
 */
static void release_address(private_attribute_manager_t *this,
							char *pool, host_t *address, identification_t *id)
{
	enumerator_t *enumerator;
	attribute_provider_t *current;
	bool found = FALSE;

	this->lock->read_lock(this->lock);
	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->release_address(current, pool, address, id))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!found)
	{
		DBG1("releasing address to pool '%s' failed", pool);
	}
}

/**
 * inner enumerator constructor for responder attributes
 */
static enumerator_t *responder_enum_create(attribute_provider_t *provider,
										   enum_data_t *data)
{
	return provider->create_attribute_enumerator(provider, data->id, data->vip);
}

/**
 * Implementation of attribute_manager_t.create_responder_enumerator
 */
static enumerator_t* create_responder_enumerator(
			private_attribute_manager_t *this, identification_t *id, host_t *vip)
{
	enum_data_t *data = malloc_thing(enum_data_t);

	data->id = id;
	data->vip = vip;
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(
				enumerator_create_nested(
					this->providers->create_enumerator(this->providers),
					(void*)responder_enum_create, data, free),
				(void*)this->lock->unlock, this->lock);
}

/**
 * Implementation of attribute_manager_t.add_provider.
 */
static void add_provider(private_attribute_manager_t *this,
						 attribute_provider_t *provider)
{
	this->lock->write_lock(this->lock);
	this->providers->insert_last(this->providers, provider);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of attribute_manager_t.remove_provider.
 */
static void remove_provider(private_attribute_manager_t *this,
							attribute_provider_t *provider)
{
	this->lock->write_lock(this->lock);
	this->providers->remove(this->providers, provider, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of attribute_manager_t.handle
 */
static attribute_handler_t* handle(private_attribute_manager_t *this,
						identification_t *server, attribute_handler_t *handler,
						configuration_attribute_type_t type, chunk_t data)
{
	enumerator_t *enumerator;
	attribute_handler_t *current, *handled = NULL;

	this->lock->read_lock(this->lock);

	/* try to find the passed handler */
	enumerator = this->handlers->create_enumerator(this->handlers);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current == handler && current->handle(current, server, type, data))
		{
			handled = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!handled)
	{	/* handler requesting this attribute not found, try any other */
		enumerator = this->handlers->create_enumerator(this->handlers);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (current->handle(current, server, type, data))
			{
				handled = current;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	this->lock->unlock(this->lock);

	if (!handled)
	{
		DBG1("handling %N attribute failed",
			 configuration_attribute_type_names, type);
	}
	return handled;
}

/**
 * Implementation of attribute_manager_t.release
 */
static void release(private_attribute_manager_t *this,
					attribute_handler_t *handler,
					identification_t *server,
					configuration_attribute_type_t type, chunk_t data)
{
	enumerator_t *enumerator;
	attribute_handler_t *current;

	this->lock->read_lock(this->lock);
	enumerator = this->handlers->create_enumerator(this->handlers);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current == handler)
		{
			current->release(current, server, type, data);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * inner enumerator constructor for initiator attributes
 */
static enumerator_t *initiator_enum_create(attribute_handler_t *handler,
										   enum_data_t *data)
{
	return handler->create_attribute_enumerator(handler, data->id, data->vip);
}

/**
 * Implementation of attribute_manager_t.create_initiator_enumerator
 */
static enumerator_t* create_initiator_enumerator(
		private_attribute_manager_t *this, identification_t *id, host_t *vip)
{
	enum_data_t *data = malloc_thing(enum_data_t);

	data->id = id;
	data->vip = vip;
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(
				enumerator_create_nested(
					this->handlers->create_enumerator(this->handlers),
					(void*)initiator_enum_create, data, free),
				(void*)this->lock->unlock, this->lock);
}

/**
 * Implementation of attribute_manager_t.add_handler
 */
static void add_handler(private_attribute_manager_t *this,
						attribute_handler_t *handler)
{
	this->lock->write_lock(this->lock);
	this->handlers->insert_last(this->handlers, handler);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of attribute_manager_t.remove_handler
 */
static void remove_handler(private_attribute_manager_t *this,
						attribute_handler_t *handler)
{
	this->lock->write_lock(this->lock);
	this->handlers->remove(this->handlers, handler, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of attribute_manager_t.destroy
 */
static void destroy(private_attribute_manager_t *this)
{
	this->providers->destroy(this->providers);
	this->handlers->destroy(this->handlers);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
attribute_manager_t *attribute_manager_create()
{
	private_attribute_manager_t *this = malloc_thing(private_attribute_manager_t);

	this->public.acquire_address = (host_t*(*)(attribute_manager_t*, char*, identification_t*,host_t*))acquire_address;
	this->public.release_address = (void(*)(attribute_manager_t*, char *, host_t*, identification_t*))release_address;
	this->public.create_responder_enumerator = (enumerator_t*(*)(attribute_manager_t*, identification_t*, host_t*))create_responder_enumerator;
	this->public.add_provider = (void(*)(attribute_manager_t*, attribute_provider_t *provider))add_provider;
	this->public.remove_provider = (void(*)(attribute_manager_t*, attribute_provider_t *provider))remove_provider;
	this->public.handle = (attribute_handler_t*(*)(attribute_manager_t*,identification_t*, attribute_handler_t*, configuration_attribute_type_t, chunk_t))handle;
	this->public.release = (void(*)(attribute_manager_t*, attribute_handler_t*, identification_t*, configuration_attribute_type_t, chunk_t))release;
	this->public.create_initiator_enumerator = (enumerator_t*(*)(attribute_manager_t*, identification_t*, host_t*))create_initiator_enumerator;
	this->public.add_handler = (void(*)(attribute_manager_t*, attribute_handler_t*))add_handler;
	this->public.remove_handler = (void(*)(attribute_manager_t*, attribute_handler_t*))remove_handler;
	this->public.destroy = (void(*)(attribute_manager_t*))destroy;

	this->providers = linked_list_create();
	this->handlers = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	return &this->public;
}

