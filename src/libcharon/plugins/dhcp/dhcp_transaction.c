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

#include "dhcp_transaction.h"

typedef struct private_dhcp_transaction_t private_dhcp_transaction_t;

/**
 * Private data of an dhcp_transaction_t object.
 */
struct private_dhcp_transaction_t {

	/**
	 * Public dhcp_transaction_t interface.
	 */
	dhcp_transaction_t public;

	/**
	 * DHCP transaction ID
	 */
	u_int32_t id;

	/**
	 * Peer identity
	 */
	identification_t *identity;

	/**
	 * received DHCP address
	 */
	host_t *address;

	/**
	 * discovered DHCP server address
	 */
	host_t *server;
};

METHOD(dhcp_transaction_t, get_id, u_int32_t,
	private_dhcp_transaction_t *this)
{
	return this->id;
}

METHOD(dhcp_transaction_t, get_identity, identification_t*,
	private_dhcp_transaction_t *this)
{
	return this->identity;
}

METHOD(dhcp_transaction_t, set_address, void,
	private_dhcp_transaction_t *this, host_t *address)
{
	DESTROY_IF(this->address);
	this->address = address;
}

METHOD(dhcp_transaction_t, get_address, host_t*,
	private_dhcp_transaction_t *this)
{
	return this->address;
}

METHOD(dhcp_transaction_t, set_server, void,
	private_dhcp_transaction_t *this, host_t *server)
{
	DESTROY_IF(this->server);
	this->server = server;
}

METHOD(dhcp_transaction_t, get_server, host_t*,
	private_dhcp_transaction_t *this)
{
	return this->server;
}

METHOD(dhcp_transaction_t, destroy, void,
	private_dhcp_transaction_t *this)
{
	this->identity->destroy(this->identity);
	DESTROY_IF(this->address);
	DESTROY_IF(this->server);
	free(this);
}

/**
 * See header
 */
dhcp_transaction_t *dhcp_transaction_create(u_int32_t id,
											identification_t *identity)
{
	private_dhcp_transaction_t *this;

	INIT(this,
		.public = {
			.get_id = _get_id,
			.get_identity = _get_identity,
			.set_address = _set_address,
			.get_address = _get_address,
			.set_server = _set_server,
			.get_server = _get_server,
			.destroy = _destroy,
		},
		.id = id,
		.identity = identity->clone(identity),
	);

	return &this->public;
}

