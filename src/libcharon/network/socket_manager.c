/*
 * Copyright (C) 2010-2012 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "socket_manager.h"

#include <daemon.h>
#include <threading/thread.h>
#include <threading/rwlock.h>
#include <collections/linked_list.h>
#include <collections/hashtable.h>

typedef struct private_socket_manager_t private_socket_manager_t;

/**
 * Private data of an socket_manager_t object.
 */
struct private_socket_manager_t {

	/**
	 * Public socket_manager_t interface.
	 */
	socket_manager_t public;
	
	/**
	 * List of socket constructors used during shutdown.
	 */
	hashtable_t *socket_constructors;

	/**
	 * Instantiated socket implementation for IP
	 */
	socket_t *ip_socket;
	
	/**
	 * Instantiated socket implementation for FC
	 */
	socket_t *fc_socket;

	/**
	 * The constructor used to create the current socket
	 */
	socket_constructor_t create;

	/**
	 * Lock for sockets list
	 */
	rwlock_t *lock;
};

METHOD(socket_manager_t, receiver, status_t,
	private_socket_manager_t *this, packet_t **packet)
{
	status_t status;
	this->lock->read_lock(this->lock);
	if (!this->ip_socket)
	{
		DBG1(DBG_NET, "no socket implementation registered, receiving failed");
		this->lock->unlock(this->lock);
		return NOT_SUPPORTED;
	}
	/* receive is blocking and the thread can be cancelled */
	thread_cleanup_push((thread_cleanup_t)this->lock->unlock, this->lock);
	status = this->ip_socket->receive(this->ip_socket, packet);
	thread_cleanup_pop(TRUE);
	return status;
}

METHOD(socket_manager_t, sender, status_t,
	private_socket_manager_t *this, packet_t *packet)
{
	status_t status;
	socket_t *socket = NULL;
	
	this->lock->read_lock(this->lock);
	host_t *src = packet->get_source (packet);
	int family = src->get_family (src);
	
	if (family == AF_NETLINK)
	{
		socket = this->fc_socket;
	}
	else
	{
		socket = this->ip_socket;
	}
	
	if (!socket)
	{
		DBG1(DBG_NET, "no socket implementation registered for family %d, sending failed", family);
		this->lock->unlock(this->lock);
		return NOT_SUPPORTED;
	}
	status = socket->send(socket, packet);
	this->lock->unlock(this->lock);
	return status;
}

METHOD(socket_manager_t, get_port, uint16_t,
	private_socket_manager_t *this, socket_family_t family, bool nat_t)
{
	uint16_t port = 0;
	socket_t *socket;
	
	this->lock->read_lock(this->lock);
	if (family == SOCKET_FAMILY_FC)
	{
		socket = this->fc_socket;
	}
	else
	{
		socket = this->ip_socket;
	}
	
	if (socket)
	{
		port = socket->get_port(socket, nat_t);
	}
	this->lock->unlock(this->lock);
	return port;
}

METHOD(socket_manager_t, supported_families, socket_family_t,
	private_socket_manager_t *this)
{
	socket_family_t families = SOCKET_FAMILY_NONE;
	
	// Supported families is not needed for fc_socket because there is only one
	// family for FC, i.e. no IPv4 and IPv6.
	
	if (this->ip_socket != NULL)
	{	
		this->lock->read_lock(this->lock);
		families = this->ip_socket->supported_families (this->ip_socket);
		this->lock->unlock(this->lock);
	}
	return families;
}

METHOD(socket_manager_t, add_socket, void,
	private_socket_manager_t *this, socket_constructor_t create)
{
	socket_t *new_socket;
	socket_family_t family;
	
	this->lock->write_lock(this->lock);
	new_socket = create();
	family = new_socket->supported_families (new_socket);
	
	if (family == SOCKET_FAMILY_FC)
	{
		if (this->fc_socket)
		{
			DBG0(DBG_NET, "Attempting to create second FC-SP socket!  Ignoring second socket.");
			DESTROY_IF (new_socket);
			new_socket = NULL;
		}
		else
		{
			this->fc_socket = new_socket;
		}
	}
	else
	{
		if (this->ip_socket)
		{
			DBG0(DBG_NET, "Attempting to create second IPsec-SP socket!  Ignoring second socket.");
			DESTROY_IF (new_socket);
			new_socket = NULL;
		}
		else
		{
			this->ip_socket = new_socket;
		}
	}
	
	if (new_socket)
	{
		this->socket_constructors->put (this->socket_constructors, (void*) create, (void*) family);
	}
	this->lock->unlock(this->lock);
}

METHOD(socket_manager_t, remove_socket, void,
	private_socket_manager_t *this, socket_constructor_t create)
{
	this->lock->write_lock(this->lock);
	
	socket_family_t family = (socket_family_t) this->socket_constructors->get (this->socket_constructors, (void*) create);
	
	if (family == SOCKET_FAMILY_FC)
	{
		this->fc_socket->destroy (this->fc_socket);
		this->fc_socket = NULL;
	}
	else
	{
		this->ip_socket->destroy (this->ip_socket);
		this->ip_socket = NULL;
	}
	this->socket_constructors->remove (this->socket_constructors, (void*) create);
	this->lock->unlock(this->lock);
}

METHOD(socket_manager_t, destroy, void,
	private_socket_manager_t *this)
{
	DESTROY_IF(this->ip_socket);
	DESTROY_IF(this->fc_socket);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
socket_manager_t *socket_manager_create()
{
	private_socket_manager_t *this;

	INIT(this,
		.public = {
			.send = _sender,
			.receive = _receiver,
			.get_port = _get_port,
			.supported_families = _supported_families,
			.add_socket = _add_socket,
			.remove_socket = _remove_socket,
			.destroy = _destroy,
		},
		.socket_constructors = hashtable_create (hashtable_hash_ptr, hashtable_equals_ptr, 8),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.ip_socket = NULL,
		.fc_socket = NULL,
	);

	return &this->public;
}

