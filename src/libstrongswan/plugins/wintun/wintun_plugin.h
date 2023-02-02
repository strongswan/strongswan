/*
 * Copyright (C) 2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup wintun_p wintun
 * @ingroup plugins
 *
 * @defgroup wintun_plugin wintun_plugin
 * @{ @ingroup wintun_p
 */

#ifndef WINTUN_PLUGIN_H_
#define WINTUN_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct wintun_plugin_t wintun_plugin_t;

/**
 * Plugin providing a Windows TUN device
 */
struct wintun_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** WINTUN_PLUGIN_H_ @}*/
