/*
 * Copyright (C) 2010 Tobias Brunner
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
 * create a plugin
 * returns: NOT_FOUND, if the constructor was not found
 *          FAILED, if the plugin could not be constructed
 */
static status_t create_plugin(private_plugin_loader_t *this, void *handle,
							  char *name, bool integrity, plugin_t **plugin)
{
	char create[128];
	plugin_constructor_t constructor;

	if (snprintf(create, sizeof(create), "%s_plugin_create",
				 name) >= sizeof(create))
	{
		return FAILED;
	}
	translate(create, "-", "_");
	constructor = dlsym(handle, create);
	if (constructor == NULL)
	{
		return NOT_FOUND;
	}
	if (integrity && lib->integrity)
	{
		if (!lib->integrity->check_segment(lib->integrity, name, constructor))
		{
			DBG1(DBG_LIB, "plugin '%s': failed segment integrity test", name);
			return FAILED;
		}
		DBG1(DBG_LIB, "plugin '%s': passed file and segment integrity tests",
			 name);
	}
	*plugin = constructor();
	if (*plugin == NULL)
	{
		DBG1(DBG_LIB, "plugin '%s': failed to load - %s returned NULL", name,
			 create);
		return FAILED;
	}
	DBG2(DBG_LIB, "plugin '%s': loaded successfully", name);
	return SUCCESS;
}

/**
 * load a single plugin
 */
static plugin_t* load_plugin(private_plugin_loader_t *this,
							 char *path, char *name)
{
	char file[PATH_MAX];
	void *handle;
	plugin_t *plugin;

	switch (create_plugin(this, RTLD_DEFAULT, name, FALSE, &plugin))
	{
		case SUCCESS:
			return plugin;
		case NOT_FOUND:
			/* try to load the plugin from a file */
			break;
		default:
			return NULL;
	}

	if (snprintf(file, sizeof(file), "%s/libstrongswan-%s.so", path,
				 name) >= sizeof(file))
	{
		return NULL;
	}
	if (lib->integrity)
	{
		if (!lib->integrity->check_file(lib->integrity, name, file))
		{
			DBG1(DBG_LIB, "plugin '%s': failed file integrity test of '%s'",
				 name, file);
			return NULL;
		}
	}
	handle = dlopen(file, RTLD_LAZY);
	if (handle == NULL)
	{
		DBG1(DBG_LIB, "plugin '%s' failed to load: %s", name, dlerror());
		return NULL;
	}
	if (create_plugin(this, handle, name, TRUE, &plugin) != SUCCESS)
	{
		dlclose(handle);
		return NULL;
	}
	/* we do not store or free dlopen() handles, leak_detective requires
	 * the modules to keep loaded until leak report */
	return plugin;
}

/**
 * Check if a plugin is already loaded
 */
static bool plugin_loaded(private_plugin_loader_t *this, char *name)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	char *current;

	enumerator = this->names->create_enumerator(this->names);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(name, current))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Implementation of plugin_loader_t.load_plugins.
 */
static bool load(private_plugin_loader_t *this, char *path, char *list)
{
	enumerator_t *enumerator;
	char *token;
	bool critical_failed = FALSE;

	if (path == NULL)
	{
		path = PLUGINDIR;
	}

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
		if (plugin_loaded(this, token))
		{
			free(token);
			continue;
		}
		plugin = load_plugin(this, path, token);
		if (plugin)
		{
			this->plugins->insert_last(this->plugins, plugin);
			this->names->insert_last(this->names, token);
		}
		else
		{
			if (critical)
			{
				critical_failed = TRUE;
				DBG1(DBG_LIB, "loading critical plugin '%s' failed", token);
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

	/* unload plugins in reverse order */
	while (this->plugins->remove_last(this->plugins,
									   (void**)&plugin) == SUCCESS)
	{
		plugin->destroy(plugin);
	}
	while (this->names->remove_last(this->names, (void**)&name) == SUCCESS)
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

