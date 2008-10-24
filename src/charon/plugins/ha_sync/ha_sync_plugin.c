/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "ha_sync_plugin.h"
#include "ha_sync_child.h"

#include <daemon.h>
#include <config/child_cfg.h>

typedef struct private_ha_sync_plugin_t private_ha_sync_plugin_t;

/**
 * private data of ha_sync plugin
 */
struct private_ha_sync_plugin_t {

	/**
	 * implements plugin interface
	 */
	ha_sync_plugin_t public;

	/**
	 * CHILD_SA sync
	 */
	ha_sync_child_t *child;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_ha_sync_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->child->listener);
	this->child->destroy(this->child);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_ha_sync_plugin_t *this = malloc_thing(private_ha_sync_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	this->child = ha_sync_child_create();
	charon->bus->add_listener(charon->bus, &this->child->listener);

	return &this->public.plugin;
}

