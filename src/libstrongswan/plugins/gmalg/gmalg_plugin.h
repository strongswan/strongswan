/*
 * Copyright (C) 2008 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup gmalg_p gmalg
 * @ingroup plugins
 *
 * @defgroup gmalg_plugin gmalg_plugin
 * @{ @ingroup gmalg_p
 */

#ifndef GMALG_PLUGIN_H_
#define GMALG_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct gmalg_plugin_t gmalg_plugin_t;

/**
 * Plugin implementing crypto functions via the gmalg library
 */
struct gmalg_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** GMALG_PLUGIN_H_ @}*/
