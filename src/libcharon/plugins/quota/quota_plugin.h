/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>
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
 * @defgroup quota quota
 * @ingroup cplugins
 *
 * @defgroup quota_plugin quota_plugin
 * @{ @ingroup quota
 */

#ifndef QUOTA_PLUGIN_H_
#define QUOTA_PLUGIN_H_

#include <plugins/plugin.h>

#include <daemon.h>

typedef struct quota_plugin_t quota_plugin_t;

/**
 * quota plugin.
 *
 * This plugin tracks network usage of connections.
 * It therefore collects information on any CHILD_SA during the lifetime of an IKE_SA.
 * The plugin calls a script similar to updown plugin.
 */
struct quota_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};


#endif /** QUOTA_PLUGIN_H_ @}*/
