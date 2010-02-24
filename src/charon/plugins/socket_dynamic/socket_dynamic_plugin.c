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

#include "socket_dynamic_plugin.h"

#include "socket_dynamic_socket.h"

#include <daemon.h>

typedef struct private_socket_dynamic_plugin_t private_socket_dynamic_plugin_t;

/**
 * Private data of socket plugin
 */
struct private_socket_dynamic_plugin_t {

	/**
	 * Implements plugin interface
	 */
	socket_dynamic_plugin_t public;

	/**
	 * Socket instance.
	 */
	socket_dynamic_socket_t *socket;
};

METHOD(plugin_t, destroy, void,
	private_socket_dynamic_plugin_t *this)
{
	charon->socket->remove_socket(charon->socket, &this->socket->socket);
	this->socket->destroy(this->socket);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_socket_dynamic_plugin_t *this;

	INIT(this,
		.public.plugin.destroy = _destroy,
		.socket = socket_dynamic_socket_create(),
	);

	if (!this->socket)
	{
		free(this);
		return NULL;
	}
	charon->socket->add_socket(charon->socket, &this->socket->socket);

	return &this->public.plugin;
}

