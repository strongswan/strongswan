/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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
 * @defgroup serpent_p serpent
 * @ingroup plugins
 *
 * @defgroup serpent_plugin serpent_plugin
 * @{ @ingroup serpent_p
 */

#ifndef SERPENT_PLUGIN_H_
#define SERPENT_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct serpent_plugin_t serpent_plugin_t;

/**
 * Plugin implementing Serpent based algorithms in software.
 */
struct serpent_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a serpent_plugin instance.
 */
plugin_t *plugin_create();

#endif /** SERPENT_PLUGIN_H_ @}*/
