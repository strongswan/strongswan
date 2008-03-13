/*
 * Copyright (C) 2007 Martin Willi
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
 * @defgroup plugin_loader plugin_loader
 * @{ @ingroup plugin
 */

#ifndef PLUGIN_LOADER_H_
#define PLUGIN_LOADER_H_

typedef struct plugin_loader_t plugin_loader_t;

/**
 * The plugin_loader loads plugins from a directory and initializes them
 */
struct plugin_loader_t {	
	
	/**
	 * Load plugins from a directory.
	 *
	 * @param path			path containing loadable plugins
	 * @param prefix		prefix of plugin libraries to load
	 * @return				number of successfully loaded plugins
	 */
	int (*load)(plugin_loader_t *this, char *path, char *prefix);
		
	/**
     * Unload loaded plugins, destroy plugin_loader instance.
     */
    void (*destroy)(plugin_loader_t *this);
};

/**
 * Create a plugin_loader instance.
 *
 * @return			plugin loader instance
 */
plugin_loader_t *plugin_loader_create();

#endif /* PLUGIN_LOADER_H_ @}*/
