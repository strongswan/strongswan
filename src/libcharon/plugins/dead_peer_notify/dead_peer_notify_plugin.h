/* vim: set ts=4 sw=4 noexpandtab: */
/*
 * Copyright (C) 2015 Pavel Balaev.
 * Copyright (C) 2015 InfoTeCS JSC.
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
 * @defgroup dead_peer_notify dead_peer_notify
 * @ingroup cplugins
 *
 * @defgroup dead_peer_notify_plugin dead_peer_notify_plugin
 * @{ @ingroup dead_peer_notify
 */

#ifndef DEAD_PEER_NOTIFY_PLUGIN_H_
#define DEAD_PEER_NOTIFY_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct dead_peer_notify_plugin_t dead_peer_notify_plugin_t;

/**
 * Plugin sending error notifications over a UNIX socket.
 */
struct dead_peer_notify_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** DEAD_PEER_NOTIFY_PLUGIN_H_ @}*/
