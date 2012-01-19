/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @{ @ingroup plugins
 */

#ifndef PLUGIN_LOADER_H_
#define PLUGIN_LOADER_H_

typedef struct plugin_loader_t plugin_loader_t;

#include <utils/enumerator.h>

/**
 * The plugin_loader loads plugins from a directory and initializes them
 */
struct plugin_loader_t {

	/**
	 * Load a list of plugins from a directory.
	 *
	 * Each plugin in list may have a ending exclamation mark (!) to mark it
	 * as a critical plugin. If loading a critical plugin fails, plugin loading
	 * is aborted and FALSE is returned.
	 *
	 * @param path			path containing loadable plugins, NULL for default
	 * @param list			space separated list of plugins to load
	 * @return				TRUE if all critical plugins loaded successfully
	 */
	bool (*load)(plugin_loader_t *this, char *path, char *list);

	/**
	 * Reload the configuration of one or multiple plugins.
	 *
	 * @param				space separated plugin names to reload, NULL for all
	 * @return				number of plugins that did support reloading
	 */
	u_int (*reload)(plugin_loader_t *this, char *list);

	/**
	 * Unload all loaded plugins.
	 */
	void (*unload)(plugin_loader_t *this);

	/**
	 * Create an enumerator over all loaded plugins.
	 *
	 * In addition to the plugin, the enumerator returns a list of pointers to
	 * plugin features currently loaded (if the argument is not NULL).
	 * This list is to be read only.
	 *
	 * @return				enumerator over plugin_t*, linked_list_t*
	 */
	enumerator_t* (*create_plugin_enumerator)(plugin_loader_t *this);

	/**
	 * Get a simple list the names of all loaded plugins.
	 *
	 * The function returns internal data, do not free.
	 *
	 * @return				list of the names of all loaded plugins
	 */
	char* (*loaded_plugins)(plugin_loader_t *this);

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

#endif /** PLUGIN_LOADER_H_ @}*/
