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

/**
 * @defgroup socket_raw socket_raw
 * @ingroup cplugins
 *
 * @defgroup socket_raw_plugin socket_raw_plugin
 * @{ @ingroup socket_raw
 */

#ifndef SOCKET_RAW_PLUGIN_H_
#define SOCKET_RAW_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct socket_raw_plugin_t socket_raw_plugin_t;

/**
 * RAW socket implementation plugin.
 */
struct socket_raw_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a socket_raw_plugin instance.
 */
plugin_t *plugin_create();

#endif /** SOCKET_RAW_PLUGIN_H_ @}*/
