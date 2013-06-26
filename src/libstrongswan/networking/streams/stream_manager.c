/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "stream_manager.h"

#include <threading/rwlock.h>

typedef struct private_stream_manager_t private_stream_manager_t;

/**
 * Private data of an stream_manager_t object.
 */
struct private_stream_manager_t {

	/**
	 * Public stream_manager_t interface.
	 */
	stream_manager_t public;

	/**
	 * List of registered stream constructors, as stream_entry_t
	 */
	linked_list_t *streams;

	/**
	 * List of registered service constructors, as service_entry_t
	 */
	linked_list_t *services;

	/**
	 * List of registered running services, as running_entry_t
	 */
	linked_list_t *running;

	/**
	 * Lock for all lists
	 */
	rwlock_t *lock;
};

/**
 * Registered stream backend
 */
typedef struct {
	/** URI prefix */
	char *prefix;
	/** constructor function */
	stream_constructor_t create;
} stream_entry_t;

/**
 * Registered service backend
 */
typedef struct {
	/** URI prefix */
	char *prefix;
	/** constructor function */
	stream_service_constructor_t create;
} service_entry_t;

/**
 * Running service
 */
typedef struct {
	/** URI of service */
	char *uri;
	/** stream accept()ing connections */
	stream_service_t *service;
} running_entry_t;

METHOD(stream_manager_t, connect_, stream_t*,
	private_stream_manager_t *this, char *uri)
{
	enumerator_t *enumerator;
	stream_entry_t *entry;
	stream_t *stream = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->streams->create_enumerator(this->streams);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (strpfx(uri, entry->prefix))
		{
			stream = entry->create(uri);
			if (stream)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	return stream;
}

METHOD(stream_manager_t, start_service, bool,
	private_stream_manager_t *this, char *uri,
	stream_service_cb_t cb, void *data)
{
	running_entry_t *running;
	enumerator_t *enumerator;
	service_entry_t *entry;
	stream_service_t *service = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->services->create_enumerator(this->services);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (strpfx(uri, entry->prefix))
		{
			service = entry->create(uri);
			if (service)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!service)
	{
		return FALSE;
	}

	INIT(running,
		.uri = strdup(uri),
		.service = service,
	);
	service->on_accept(service, cb, data);

	this->lock->write_lock(this->lock);
	this->running->insert_last(this->running, running);
	this->lock->unlock(this->lock);

	return TRUE;
}

METHOD(stream_manager_t, stop_service, void,
	private_stream_manager_t *this, char *uri)
{
	enumerator_t *enumerator;
	running_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->running->create_enumerator(this->running);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(entry->uri, uri))
		{
			this->running->remove_at(this->running, enumerator);
			entry->service->destroy(entry->service);
			free(entry->uri);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(stream_manager_t, add_stream, void,
	private_stream_manager_t *this, char *prefix, stream_constructor_t create)
{
	stream_entry_t *entry;

	INIT(entry,
		.prefix = strdup(prefix),
		.create = create,
	);

	this->lock->write_lock(this->lock);
	this->streams->insert_last(this->streams, entry);
	this->lock->unlock(this->lock);
}

METHOD(stream_manager_t, remove_stream, void,
	private_stream_manager_t *this, stream_constructor_t create)
{
	enumerator_t *enumerator;
	stream_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->streams->create_enumerator(this->streams);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->streams->remove_at(this->streams, enumerator);
			free(entry->prefix);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(stream_manager_t, add_service, void,
	private_stream_manager_t *this, char *prefix,
	stream_service_constructor_t create)
{
	service_entry_t *entry;

	INIT(entry,
		.prefix = strdup(prefix),
		.create = create,
	);

	this->lock->write_lock(this->lock);
	this->services->insert_last(this->services, entry);
	this->lock->unlock(this->lock);
}

METHOD(stream_manager_t, remove_service, void,
	private_stream_manager_t *this, stream_service_constructor_t create)
{
	enumerator_t *enumerator;
	service_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->services->create_enumerator(this->services);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->services->remove_at(this->services, enumerator);
			free(entry->prefix);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(stream_manager_t, destroy, void,
	private_stream_manager_t *this)
{
	remove_stream(this, stream_create_unix);

	this->streams->destroy(this->streams);
	this->services->destroy(this->services);
	this->running->destroy(this->running);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
stream_manager_t *stream_manager_create()
{
	private_stream_manager_t *this;

	INIT(this,
		.public = {
			.connect = _connect_,
			.start_service = _start_service,
			.stop_service = _stop_service,
			.add_stream = _add_stream,
			.remove_stream = _remove_stream,
			.add_service = _add_service,
			.remove_service = _remove_service,
			.destroy = _destroy,
		},
		.streams = linked_list_create(),
		.services = linked_list_create(),
		.running = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	add_stream(this, "unix://", stream_create_unix);

	return &this->public;
}
