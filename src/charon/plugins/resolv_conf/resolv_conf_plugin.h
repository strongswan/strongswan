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

/**
 * @defgroup resolv_conf resolv_conf
 * @ingroup cplugins
 *
 * @defgroup resolv_conf_plugin resolv_conf_plugin
 * @{ @ingroup resolv_conf
 */

#ifndef RESOLV_CONF_PLUGIN_H_
#define RESOLV_CONF_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct resolv_conf_plugin_t resolv_conf_plugin_t;

/**
 * Plugin that writes received DNS servers in a resolv.conf file.
 */
struct resolv_conf_plugin_t {
	
	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a resolv_conf_plugin instance.
 */
plugin_t *plugin_create();

#endif /** RESOLV_CONF_PLUGIN_H_ @}*/
