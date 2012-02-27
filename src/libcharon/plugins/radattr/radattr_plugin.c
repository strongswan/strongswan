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

#include "radattr_plugin.h"

#include "radattr_listener.h"

#include <daemon.h>

typedef struct private_radattr_plugin_t private_radattr_plugin_t;

/**
 * private data of radattr plugin
 */
struct private_radattr_plugin_t {

	/**
	 * implements plugin interface
	 */
	radattr_plugin_t public;

	/**
	 * Listener acting on messages
	 */
	radattr_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
	private_radattr_plugin_t *this)
{
	return "radattr";
}

METHOD(plugin_t, destroy, void,
	private_radattr_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->listener->listener);
	this->listener->destroy(this->listener);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *radattr_plugin_create()
{
	private_radattr_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.listener = radattr_listener_create(),
	);

	charon->bus->add_listener(charon->bus, &this->listener->listener);

	return &this->public.plugin;
}
