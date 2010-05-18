/*
 * Copyright (C) 2010 Andreas Steffen
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
 * @defgroup xauth xauth
 * @ingroup pplugins
 *
 * @defgroup xauth_plugin xauth_plugin
 * @{ @ingroup xauth
 */

#ifndef XAUTH_PLUGIN_H_
#define XAUTH_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct xauth_plugin_t xauth_plugin_t;

/**
 * XAUTH plugin
 */
struct xauth_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** XAUTH_PLUGIN_H_ @}*/
