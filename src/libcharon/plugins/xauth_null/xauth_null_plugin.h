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
 */

/**
 * @defgroup xauth_null xauth_null
 * @ingroup cplugins
 *
 * @defgroup xauth_null_plugin xauth_null_plugin
 * @{ @ingroup xauth_null
 */

#ifndef XAUTH_NULL_PLUGIN_H_
#define XAUTH_NULL_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct xauth_null_plugin_t xauth_null_plugin_t;

/**
 * XAUTH Null plugin.
 */
struct xauth_null_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** XAUTH_NULL_PLUGIN_H_ @}*/
