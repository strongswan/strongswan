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
	 * Listener interface, listens to CHILD_SA state changes
	 */
	listener_t listener;
};

/**
 * Listener implementation
 */
static bool child_state_change(listener_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	if (state == CHILD_INSTALLED)
	{
		chunk_t chunk;

		chunk = child_sa->serialize(child_sa);
		DBG1(DBG_IKE, "NEW CHILD: %B", &chunk);

		chunk_clear(&chunk);
	}
	return TRUE;
}

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_ha_sync_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->listener);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_ha_sync_plugin_t *this = malloc_thing(private_ha_sync_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	memset(&this->listener, 0, sizeof(listener_t));
	this->listener.child_state_change = child_state_change;

	charon->bus->add_listener(charon->bus, &this->listener);

	return &this->public.plugin;
}

