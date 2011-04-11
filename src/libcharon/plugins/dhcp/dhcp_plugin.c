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

#include "dhcp_plugin.h"

#include <hydra.h>
#include <daemon.h>

#include "dhcp_socket.h"
#include "dhcp_provider.h"

typedef struct private_dhcp_plugin_t private_dhcp_plugin_t;

/**
 * private data of dhcp plugin
 */
struct private_dhcp_plugin_t {

	/**
	 * implements plugin interface
	 */
	dhcp_plugin_t public;

	/**
	 * DHCP communication socket
	 */
	dhcp_socket_t *socket;

	/**
	 * Attribute provider
	 */
	dhcp_provider_t *provider;
};

METHOD(plugin_t, get_name, char*,
	private_dhcp_plugin_t *this)
{
	return "dhcp";
}

METHOD(plugin_t, destroy, void,
	private_dhcp_plugin_t *this)
{
	hydra->attributes->remove_provider(hydra->attributes,
									   &this->provider->provider);
	this->provider->destroy(this->provider);
	this->socket->destroy(this->socket);
	free(this);
}

/**
 * Plugin constructor.
 */
plugin_t *dhcp_plugin_create()
{
	private_dhcp_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.socket = dhcp_socket_create(),
	);

	if (!this->socket)
	{
		free(this);
		return NULL;
	}

	this->provider = dhcp_provider_create(this->socket);
	hydra->attributes->add_provider(hydra->attributes,
									&this->provider->provider);

	return &this->public.plugin;
}

