/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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
 * @defgroup narrowid narrowid
 * @ingroup cplugins
 *
 * @defgroup narrowid_plugin narrowid_plugin
 * @{ @ingroup narrowid
 */

#ifndef NARROWID_PLUGIN_H_
#define NARROWID_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct narrowid_plugin_t narrowid_plugin_t;

/**
 * Plugin narrowing remote traffic selectors to its authenticated IKE IDs.
 */
struct narrowid_plugin_t {

	/**
	 * Implements plugin_t. interface.
	 */
	plugin_t plugin;
};

#endif /** NARROWID_PLUGIN_H_ @}*/
