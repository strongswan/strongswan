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
 * @defgroup cga_p cga
 * @ingroup plugins
 *
 * @defgroup cga_plugin cga_plugin
 * @{ @ingroup cga_p
 */

#ifndef CGA_PLUGIN_H_
#define CGA_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct cga_plugin_t cga_plugin_t;

/**
 * Plugin implementing IPv6 Cryptographically Generated Address support
 */
struct cga_plugin_t {

	/**
	 * Implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** CGA_PLUGIN_H_ @}*/
