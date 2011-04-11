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

#include "farp_plugin.h"

#include "farp_listener.h"
#include "farp_spoofer.h"

#include <daemon.h>

typedef struct private_farp_plugin_t private_farp_plugin_t;

/**
 * private data of farp plugin
 */
struct private_farp_plugin_t {

	/**
	 * implements plugin interface
	 */
	farp_plugin_t public;

	/**
	 * Listener registering active virtual IPs
	 */
	farp_listener_t *listener;

	/**
	 * Spoofer listening and spoofing ARP messages
	 */
	farp_spoofer_t *spoofer;
};

METHOD(plugin_t, get_name, char*,
	private_farp_plugin_t *this)
{
	return "farp";
}

METHOD(plugin_t, destroy, void,
	private_farp_plugin_t *this)
{
	DESTROY_IF(this->spoofer);
	charon->bus->remove_listener(charon->bus, &this->listener->listener);
	this->listener->destroy(this->listener);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *farp_plugin_create()
{
	private_farp_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.listener = farp_listener_create(),
	);

	charon->bus->add_listener(charon->bus, &this->listener->listener);

	this->spoofer = farp_spoofer_create(this->listener);
	if (!this->spoofer)
	{
		destroy(this);
		return NULL;
	}
	return &this->public.plugin;
}

