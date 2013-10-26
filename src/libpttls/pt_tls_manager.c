/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "pt_tls_manager.h"

#include <collections/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_pt_tls_manager_t private_pt_tls_manager_t;

/**
 * Private data of an pt_tls_manager_t object.
 */
struct private_pt_tls_manager_t {

	/**
	 * Public pt_tls_manager_t interface.
	 */
	pt_tls_manager_t public;

	/**
	 * Constructor for PT-TLS connection instance
	 */
	pt_tls_connection_constructor_t create;

	/**
	 * list of added PT-TLS connections
	 */
	linked_list_t *connections;

	/**
	 * lock for lists above
	 */
	rwlock_t *lock;
};

METHOD(pt_tls_manager_t, create_connection, pt_tls_connection_t*,
	private_pt_tls_manager_t *this, tnccs_t *tnccs,	host_t *host,
	identification_t *server, identification_t *client)
{
	return this->create(tnccs, host, server, client);
}

METHOD(pt_tls_manager_t, add_connection, void,
	private_pt_tls_manager_t *this, pt_tls_connection_t *connection)
{
	this->lock->write_lock(this->lock);
	this->connections->insert_last(this->connections, connection);
	this->lock->unlock(this->lock);
}

METHOD(pt_tls_manager_t, remove_connection, void,
	private_pt_tls_manager_t *this, pt_tls_connection_t *connection)
{
	this->lock->write_lock(this->lock);
	this->connections->remove(this->connections, connection, NULL);
	this->lock->unlock(this->lock);
}

METHOD(pt_tls_manager_t, create_connection_enumerator, enumerator_t*,
	private_pt_tls_manager_t *this)
{
	return this->connections->create_enumerator(this->connections);
}

METHOD(pt_tls_manager_t, destroy, void,
	private_pt_tls_manager_t *this)
{
	this->connections->destroy_offset(this->connections,
							   offsetof(pt_tls_connection_t, destroy));
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
pt_tls_manager_t *pt_tls_manager_create(pt_tls_connection_constructor_t create)
{
	private_pt_tls_manager_t *this;

	INIT(this,
		.public = {
			.create_connection = _create_connection,
			.add_connection = _add_connection,
			.remove_connection = _remove_connection,
			.create_connection_enumerator = _create_connection_enumerator,
			.destroy = _destroy,
		},
		.create = create,
		.connections = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
