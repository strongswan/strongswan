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
 *
 * $Id$
 */

#include "plugin_loader.h"

#include <dlfcn.h>

#include <debug.h>
#include <utils/linked_list.h>
#include <plugins/plugin.h>

typedef struct private_plugin_loader_t private_plugin_loader_t;

/**
 * private data of plugin_loader
 */
struct private_plugin_loader_t {

	/**
	 * public functions
	 */
	plugin_loader_t public;
	
	/**
	 * list of loaded plugins
	 */
	linked_list_t *plugins;
};

/**
 * Implementation of plugin_loader_t.load_plugins.
 */
static int load(private_plugin_loader_t *this, char *path, char *prefix)
{
	enumerator_t *enumerator;
	char *file, *ending, *rel;
	void *handle;
	int count = 0;
	
	enumerator = enumerator_create_directory(path);
	if (!enumerator)
	{
		DBG1("opening plugin directory %s failed", path);
		return 0;
	}
	DBG2("loading plugins from %s", path);
	while (enumerator->enumerate(enumerator, &rel, &file, NULL))
	{
		plugin_t *plugin;
		plugin_constructor_t constructor;
		
		ending = file + strlen(file) - 3;
		if (ending <= file || !streq(ending, ".so"))
		{	/* only process .so libraries */
			continue;
		}
		if (!strneq(prefix, rel, strlen(prefix)))
		{
			continue;
		}
		handle = dlopen(file, RTLD_LAZY);
		if (handle == NULL)
		{
			DBG1("loading plugin %s failed: %s", rel, dlerror());
			continue;
		}
		constructor = dlsym(handle, "plugin_create");
		if (constructor == NULL)
		{
			DBG1("plugin %s has no plugin_create() function, skipped", rel);
			dlclose(handle);
			continue;
		}
		plugin = constructor();
		if (plugin == NULL)
		{
			DBG1("plugin %s constructor failed, skipping", rel);
			dlclose(handle);
			continue;
		}
		DBG2("plugin %s loaded successfully", rel);
		/* insert in front to destroy them in reverse order */
		this->plugins->insert_last(this->plugins, plugin);
		/* we do not store or free dlopen() handles, leak_detective requires
		 * the modules to keep loaded until leak report */
		count++;
	}
	enumerator->destroy(enumerator);
	return count;
}

/**
 * Implementation of plugin_loader_t.destroy
 */
static void destroy(private_plugin_loader_t *this)
{
	this->plugins->destroy_offset(this->plugins, offsetof(plugin_t, destroy));
	free(this);
}

/*
 * see header file
 */
plugin_loader_t *plugin_loader_create()
{
	private_plugin_loader_t *this = malloc_thing(private_plugin_loader_t);
	
	this->public.load = (int(*)(plugin_loader_t*, char *path, char *prefix))load;
	this->public.destroy = (void(*)(plugin_loader_t*))destroy;
	
	this->plugins = linked_list_create();
	
	return &this->public;
}

