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

#define _GNU_SOURCE
#include "plugin_loader.h"

#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>

#include <debug.h>
#include <integrity_checker.h>
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

	/**
	 * names of loaded plugins
	 */
	linked_list_t *names;
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

	if (lib->integrity)
	{
		if (!lib->integrity->check_file(lib->integrity, name, file))
		{
			DBG1("plugin '%s': failed file integrity test of '%s'", name, file);
			return NULL;
		}
	}
	handle = dlopen(file, RTLD_LAZY);
	if (handle == NULL)
	{
		DBG1("plugin '%s': failed to load '%s' - %s", name, file, dlerror());
		return NULL;
	}
	constructor = dlsym(handle, "plugin_create");
	if (constructor == NULL)
	{
		DBG1("plugin '%s': failed to load - no plugin_create() function", name);
		dlclose(handle);
		return NULL;
	}
	if (lib->integrity)
	{
		if (!lib->integrity->check_segment(lib->integrity, name, constructor))
		{
			DBG1("plugin '%s': failed segment integrity test", name);
			dlclose(handle);
			return NULL;
		}
		DBG1("plugin '%s': passed file and segment integrity tests", name);
	}
	plugin = constructor();
	if (plugin == NULL)
	{
		DBG1("plugin '%s': failed to load - plugin_create() returned NULL", name);
		dlclose(handle);
		return NULL;
	}
	DBG2("plugin '%s': loaded successfully", name);

	/* we do not store or free dlopen() handles, leak_detective requires
	 * the modules to keep loaded until leak report */
	return plugin;
}

/**
 * Implementation of plugin_loader_t.load_plugins.
 */
static bool load(private_plugin_loader_t *this, char *path, char *list)
{
	enumerator_t *enumerator;
	char *token;
	bool critical_failed = FALSE;

	enumerator = enumerator_create_token(list, " ", " ");
	while (!critical_failed && enumerator->enumerate(enumerator, &token))
	{
		plugin_t *plugin;
		bool critical = FALSE;
		int len;

		token = strdup(token);
		len = strlen(token);
		if (token[len-1] == '!')
		{
			critical = TRUE;
			token[len-1] = '\0';
		}
		plugin = load_plugin(this, path, token);
		if (plugin)
		{
			/* insert in front to destroy them in reverse order */
			this->plugins->insert_last(this->plugins, plugin);
			this->names->insert_last(this->names, token);
		}
		else
		{
			if (critical)
			{
				critical_failed = TRUE;
				DBG1("loading critical plugin '%s' failed", token);
			}
			free(token);
		}
	}
	enumerator->destroy(enumerator);
	return !critical_failed;
}

/**
 * Implementation of plugin_loader_t.unload
 */
static void unload(private_plugin_loader_t *this)
{
	plugin_t *plugin;
	char *name;

	while (this->plugins->remove_first(this->plugins,
									   (void**)&plugin) == SUCCESS)
	{
		plugin->destroy(plugin);
	}
	while (this->names->remove_first(this->names, (void**)&name) == SUCCESS)
	{
		free(name);
	}
}

/**
 * Implementation of plugin_loader_t.create_plugin_enumerator
 */
static enumerator_t* create_plugin_enumerator(private_plugin_loader_t *this)
{
	return this->names->create_enumerator(this->names);
}

/**
 * Implementation of plugin_loader_t.destroy
 */
static void destroy(private_plugin_loader_t *this)
{
	this->plugins->destroy_offset(this->plugins, offsetof(plugin_t, destroy));
	this->names->destroy_function(this->names, free);
	free(this);
}

/*
 * see header file
 */
plugin_loader_t *plugin_loader_create()
{
	private_plugin_loader_t *this = malloc_thing(private_plugin_loader_t);

	this->public.load = (bool(*)(plugin_loader_t*, char *path, char *prefix))load;
	this->public.unload = (void(*)(plugin_loader_t*))unload;
	this->public.create_plugin_enumerator = (enumerator_t*(*)(plugin_loader_t*))create_plugin_enumerator;
	this->public.destroy = (void(*)(plugin_loader_t*))destroy;

	this->plugins = linked_list_create();
	this->names = linked_list_create();

	return &this->public;
}

