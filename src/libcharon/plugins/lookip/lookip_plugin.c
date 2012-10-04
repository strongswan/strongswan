/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "lookip_plugin.h"

#include "lookip_listener.h"
#include "lookip_socket.h"

#include <daemon.h>

typedef struct private_lookip_plugin_t private_lookip_plugin_t;

/**
 * private data of lookip plugin
 */
struct private_lookip_plugin_t {

	/**
	 * implements plugin interface
	 */
	lookip_plugin_t public;

	/**
	 * Listener collecting virtual IP assignements
	 */
	lookip_listener_t *listener;

	/**
	 * UNIX socket to serve client queries
	 */
	lookip_socket_t *socket;
};

METHOD(plugin_t, get_name, char*,
	private_lookip_plugin_t *this)
{
	return "lookip";
}

METHOD(plugin_t, destroy, void,
	private_lookip_plugin_t *this)
{
	this->socket->destroy(this->socket);
	charon->bus->remove_listener(charon->bus, &this->listener->listener);
	this->listener->destroy(this->listener);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *lookip_plugin_create()
{
	private_lookip_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.listener = lookip_listener_create(),
	);

	charon->bus->add_listener(charon->bus, &this->listener->listener);
	this->socket = lookip_socket_create(this->listener);

	return &this->public.plugin;
}
