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

/**
 * @defgroup ha_sync ha_sync
 * @ingroup cplugins
 *
 * @defgroup ha_sync_plugin ha_sync_plugin
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_PLUGIN_H_
#define HA_SYNC_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct ha_sync_plugin_t ha_sync_plugin_t;

/**
 * Plugin to synchronize state in a high availability cluster.
 */
struct ha_sync_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a ha_sync_plugin instance.
 */
plugin_t *plugin_create();

#endif /* HA_SYNC_PLUGIN_H_ @}*/
