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

#include "attr_plugin.h"
#include "attr_provider.h"

#include <daemon.h>

typedef struct private_attr_plugin_t private_attr_plugin_t;

/**
 * private data of attr plugin
 */
struct private_attr_plugin_t {

	/**
	 * implements plugin interface
	 */
	attr_plugin_t public;

	/**
	 * CFG attributes provider
	 */
	attr_provider_t *provider;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_attr_plugin_t *this)
{
	lib->attributes->remove_provider(lib->attributes, &this->provider->provider);
	this->provider->destroy(this->provider);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_attr_plugin_t *this = malloc_thing(private_attr_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	this->provider = attr_provider_create();
	lib->attributes->add_provider(lib->attributes, &this->provider->provider);

	return &this->public.plugin;
}

