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

#define _GNU_SOURCE
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>

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
 * load a single plugin
 */
static plugin_t* load_plugin(private_plugin_loader_t *this,
							 char *path, char *name)
{
	char file[PATH_MAX];
	void *handle;
	plugin_t *plugin;
	plugin_constructor_t constructor;
	
	snprintf(file, sizeof(file), "%s/libstrongswan-%s.so", path, name);
	
	handle = dlopen(file, RTLD_LAZY);
	if (handle == NULL)
	{
		DBG1("loading plugin '%s' failed: %s", name, dlerror());
		return NULL;
	}
	constructor = dlsym(handle, "plugin_create");
	if (constructor == NULL)
	{
		DBG1("loading plugin '%s' failed: no plugin_create() function", name);
		dlclose(handle);
		return NULL;
	}
	plugin = constructor();
	if (plugin == NULL)
	{
		DBG1("loading plugin '%s' failed: plugin_create() returned NULL", name);
		dlclose(handle);
		return NULL;
	}
	DBG2("plugin '%s' loaded successfully", name);
	
	/* we do not store or free dlopen() handles, leak_detective requires
	 * the modules to keep loaded until leak report */
	return plugin;
}

/**
 * Implementation of plugin_loader_t.load_plugins.
 */
static int load(private_plugin_loader_t *this, char *path, char *list)
{
	plugin_t *plugin;
	char *pos;
	int count = 0;
	
	list = strdupa(list);
	while (TRUE)
	{
		pos = strchr(list, ' ');
		if (pos)
		{
			*pos++ = '\0';
			while (*pos == ' ')
			{
				pos++;
			}
			if (!*pos)
			{
				break;
			}
		}
		plugin = load_plugin(this, path, list);
		if (plugin)
		{	/* insert in front to destroy them in reverse order */
			this->plugins->insert_last(this->plugins, plugin);
			count++;
		}
		if (!pos)
		{
			break;
		}
		list = pos;
	}
	return count;
}

/**
 * Implementation of plugin_loader_t.unload
 */
static void unload(private_plugin_loader_t *this)
{
	plugin_t *plugin;
	
	while (this->plugins->remove_first(this->plugins,
									   (void**)&plugin) == SUCCESS)
	{
		plugin->destroy(plugin);
	}
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
	this->public.unload = (void(*)(plugin_loader_t*))unload;
	this->public.destroy = (void(*)(plugin_loader_t*))destroy;
	
	this->plugins = linked_list_create();
	
	return &this->public;
}

