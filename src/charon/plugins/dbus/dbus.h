/*
 * Copyright (C) 2007-2008 Martin Willi
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

/**
 * @defgroup dbus dbus
 * @ingroup cplugins
 *
 * @defgroup dbus_i dbus
 * @{ @ingroup dbus
 */

#ifndef DBUS_H_
#define DBUS_H_

#include <plugins/plugin.h>

typedef struct dbus_t dbus_t;

/**
 * NetworkManager DBUS control plugin.
 *
 * This plugin uses a DBUS connection. It is designed to work in conjuction
 * with NetworkManager to configure and control the daemon.
 */
struct dbus_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a dbus plugin instance.
 */
plugin_t *plugin_create();

#endif /* DBUS_H_ @}*/
