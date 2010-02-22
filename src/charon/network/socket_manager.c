/*
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
#include <utils/linked_list.h>

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
	 * List of registered socket
	 */
	linked_list_t *sockets;

	/**
	 * Lock for sockets list
	 */
	rwlock_t *lock;
};

METHOD(socket_manager_t, receiver, status_t,
	private_socket_manager_t *this, packet_t **packet)
{
	socket_t *socket;
	status_t status;

	this->lock->read_lock(this->lock);
	if (this->sockets->get_first(this->sockets, (void**)&socket) != SUCCESS)
	{
		DBG1(DBG_NET, "no socket implementation registered, receiving failed");
		this->lock->unlock(this->lock);
		return NOT_SUPPORTED;
	}
	/* receive is blocking and the thread can be cancelled */
	thread_cleanup_push((thread_cleanup_t)this->lock->unlock, this->lock);
	status = socket->receive(socket, packet);
	thread_cleanup_pop(TRUE);
	return status;
}

METHOD(socket_manager_t, sender, status_t,
	private_socket_manager_t *this, packet_t *packet)
{
	socket_t *socket;
	status_t status;

	this->lock->read_lock(this->lock);
	if (this->sockets->get_first(this->sockets, (void**)&socket) != SUCCESS)
	{
		DBG1(DBG_NET, "no socket implementation registered, sending failed");
		this->lock->unlock(this->lock);
		return NOT_SUPPORTED;
	}
	status = socket->send(socket, packet);
	this->lock->unlock(this->lock);
	return status;
}

METHOD(socket_manager_t, create_enumerator, enumerator_t*,
	private_socket_manager_t *this)
{
	socket_t *socket;

	this->lock->read_lock(this->lock);
	if (this->sockets->get_first(this->sockets, (void**)&socket) != SUCCESS)
	{
		this->lock->unlock(this->lock);
		return enumerator_create_empty();
	}
	return enumerator_create_cleaner(socket->create_enumerator(socket),
									 (void*)this->lock->unlock, this->lock);
}

METHOD(socket_manager_t, add_socket, void,
	private_socket_manager_t *this, socket_t *socket)
{
	this->lock->write_lock(this->lock);
	this->sockets->insert_last(this->sockets, socket);
	this->lock->unlock(this->lock);
}

METHOD(socket_manager_t, remove_socket, void,
	private_socket_manager_t *this, socket_t *socket)
{
	this->lock->write_lock(this->lock);
	this->sockets->remove(this->sockets, socket, NULL);
	this->lock->unlock(this->lock);
}

METHOD(socket_manager_t, destroy, void,
	private_socket_manager_t *this)
{
	this->sockets->destroy(this->sockets);
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
			.create_enumerator = _create_enumerator,
			.add_socket = _add_socket,
			.remove_socket = _remove_socket,
			.destroy = _destroy,
		},
		.sockets = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

