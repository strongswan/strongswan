/*
 * Copyright (C) 2009 Martin Willi
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

#include "resolve_plugin.h"
#include "resolve_handler.h"

#include <hydra.h>

typedef struct private_resolve_plugin_t private_resolve_plugin_t;

/**
 * private data of resolve plugin
 */
struct private_resolve_plugin_t {

	/**
	 * implements plugin interface
	 */
	resolve_plugin_t public;

	/**
	 * The registered DNS attribute handler
	 */
	resolve_handler_t *handler;
};

METHOD(plugin_t, get_name, char*,
	private_resolve_plugin_t *this)
{
	return "resolve";
}

METHOD(plugin_t, destroy, void,
	private_resolve_plugin_t *this)
{
	hydra->attributes->remove_handler(hydra->attributes, &this->handler->handler);
	this->handler->destroy(this->handler);
	free(this);
}

/*
 * see header file
 */
plugin_t *resolve_plugin_create()
{
	private_resolve_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.handler = resolve_handler_create(),
	);
	hydra->attributes->add_handler(hydra->attributes, &this->handler->handler);

	return &this->public.plugin;
}

