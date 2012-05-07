/*
 * Copyright (C) 2010-2012 Tobias Brunner
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
#include <library.h>
#include <integrity_checker.h>
#include <utils/linked_list.h>
#include <plugins/plugin.h>

typedef struct private_plugin_loader_t private_plugin_loader_t;
typedef struct plugin_entry_t plugin_entry_t;

/**
 * private data of plugin_loader
 */
struct private_plugin_loader_t {

	/**
	 * public functions
	 */
	plugin_loader_t public;

	/**
	 * List of plugins, as plugin_entry_t
	 */
	linked_list_t *plugins;

	/**
	 * List of names of loaded plugins
	 */
	char *loaded_plugins;
};

/**
 * Entry for a plugin
 */
struct plugin_entry_t {

	/**
	 * Plugin instance
	 */
	plugin_t *plugin;

	/**
	 * dlopen handle, if in separate lib
	 */
	void *handle;

	/**
	 * List of loaded features
	 */
	linked_list_t *loaded;

	/**
	 * List features failed to load
	 */
	linked_list_t *failed;
};

/**
 * Destroy a plugin entry
 */
static void plugin_entry_destroy(plugin_entry_t *entry)
{
	DESTROY_IF(entry->plugin);
	if (entry->handle)
	{
		dlclose(entry->handle);
	}
	entry->loaded->destroy(entry->loaded);
	entry->failed->destroy(entry->failed);
	free(entry);
}

/**
 * create a plugin
 * returns: NOT_FOUND, if the constructor was not found
 *          FAILED, if the plugin could not be constructed
 */
static status_t create_plugin(private_plugin_loader_t *this, void *handle,
						char *name, bool integrity, plugin_entry_t **entry)
{
	char create[128];
	plugin_t *plugin;
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
	plugin = constructor();
	if (plugin == NULL)
	{
		DBG1(DBG_LIB, "plugin '%s': failed to load - %s returned NULL", name,
			 create);
		return FAILED;
	}
	INIT(*entry,
		.plugin = plugin,
		.loaded = linked_list_create(),
		.failed = linked_list_create(),
	);
	DBG2(DBG_LIB, "plugin '%s': loaded successfully", name);
	return SUCCESS;
}

/**
 * load a single plugin
 */
static bool load_plugin(private_plugin_loader_t *this, char *name, char *file)
{
	plugin_entry_t *entry;
	void *handle;

	switch (create_plugin(this, RTLD_DEFAULT, name, FALSE, &entry))
	{
		case SUCCESS:
			this->plugins->insert_last(this->plugins, entry);
			return TRUE;
		case NOT_FOUND:
			/* try to load the plugin from a file */
			break;
		default:
			return FALSE;
	}
	if (lib->integrity)
	{
		if (!lib->integrity->check_file(lib->integrity, name, file))
		{
			DBG1(DBG_LIB, "plugin '%s': failed file integrity test of '%s'",
				 name, file);
			return FALSE;
		}
	}
	handle = dlopen(file, RTLD_LAZY);
	if (handle == NULL)
	{
		DBG1(DBG_LIB, "plugin '%s' failed to load: %s", name, dlerror());
		return FALSE;
	}
	if (create_plugin(this, handle, name, TRUE, &entry) != SUCCESS)
	{
		dlclose(handle);
		return FALSE;
	}
	entry->handle = handle;
	this->plugins->insert_last(this->plugins, entry);
	return TRUE;
}

/**
 * Convert enumerated entries to plugin_t
 */
static bool plugin_filter(void *null, plugin_entry_t **entry, plugin_t **plugin,
						  void *in, linked_list_t **list)
{
	*plugin = (*entry)->plugin;
	if (list)
	{
		*list = (*entry)->loaded;
	}
	return TRUE;
}

METHOD(plugin_loader_t, create_plugin_enumerator, enumerator_t*,
	private_plugin_loader_t *this)
{
	return enumerator_create_filter(
							this->plugins->create_enumerator(this->plugins),
							(void*)plugin_filter, NULL, NULL);
}

/**
 * Create a list of the names of all loaded plugins
 */
static char* loaded_plugins_list(private_plugin_loader_t *this)
{
	int buf_len = 128, len = 0;
	char *buf, *name;
	enumerator_t *enumerator;
	plugin_t *plugin;

	buf = malloc(buf_len);
	buf[0] = '\0';
	enumerator = create_plugin_enumerator(this);
	while (enumerator->enumerate(enumerator, &plugin, NULL))
	{
		name = plugin->get_name(plugin);
		if (len + (strlen(name) + 1) >= buf_len)
		{
			buf_len <<= 1;
			buf = realloc(buf, buf_len);
		}
		len += snprintf(&buf[len], buf_len - len, "%s ", name);
	}
	enumerator->destroy(enumerator);
	if (len > 0 && buf[len - 1] == ' ')
	{
		buf[len - 1] = '\0';
	}
	return buf;
}


/**
 * Check if a plugin is already loaded
 */
static bool plugin_loaded(private_plugin_loader_t *this, char *name)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	plugin_t *plugin;

	enumerator = create_plugin_enumerator(this);
	while (enumerator->enumerate(enumerator, &plugin, NULL))
	{
		if (streq(plugin->get_name(plugin), name))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Check if a feature of a plugin is already loaded
 */
static bool feature_loaded(private_plugin_loader_t *this, plugin_entry_t *entry,
						   plugin_feature_t *feature)
{
	return entry->loaded->find_first(entry->loaded, NULL,
									 (void**)&feature) == SUCCESS;
}

/**
 * Check if loading a feature of a plugin failed
 */
static bool feature_failed(private_plugin_loader_t *this, plugin_entry_t *entry,
						   plugin_feature_t *feature)
{
	return entry->failed->find_first(entry->failed, NULL,
									 (void**)&feature) == SUCCESS;
}

/**
 * Check if dependencies are satisfied
 */
static bool dependencies_satisfied(private_plugin_loader_t *this,
								plugin_entry_t *entry, bool soft, bool report,
								plugin_feature_t *features, int count)
{
	int i;

	/* first entry is provided feature, followed by dependencies */
	for (i = 1; i < count; i++)
	{
		enumerator_t *entries, *loaded;
		plugin_feature_t *feature;
		plugin_entry_t *current;
		bool found = FALSE;

		if (features[i].kind != FEATURE_DEPENDS &&
			features[i].kind != FEATURE_SDEPEND)
		{	/* end of dependencies */
			break;
		}
		entries = this->plugins->create_enumerator(this->plugins);
		while (entries->enumerate(entries, &current))
		{
			loaded = current->loaded->create_enumerator(current->loaded);
			while (loaded->enumerate(loaded, &feature))
			{
				if (plugin_feature_matches(&features[i], feature))
				{
					found = TRUE;
					break;
				}
			}
			loaded->destroy(loaded);
		}
		entries->destroy(entries);

		if (!found && (features[i].kind != FEATURE_SDEPEND || soft))
		{
			if (report)
			{
				char *provide, *depend, *name;

				name = entry->plugin->get_name(entry->plugin);
				provide = plugin_feature_get_string(&features[0]);
				depend = plugin_feature_get_string(&features[i]);
				DBG2(DBG_LIB, "feature %s in '%s' plugin has unsatisfied "
					 "dependency: %s", provide, name, depend);
				free(provide);
				free(depend);
			}
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Check if a given feature is still required as dependency
 */
static bool dependency_required(private_plugin_loader_t *this,
								plugin_feature_t *dep)
{
	enumerator_t *enumerator;
	plugin_feature_t *features;
	plugin_entry_t *entry;
	int count, i;

	enumerator = this->plugins->create_enumerator(this->plugins);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->plugin->get_features)
		{	/* features not supported */
			continue;
		}
		count = entry->plugin->get_features(entry->plugin, &features);
		for (i = 0; i < count; i++)
		{
			if (feature_loaded(this, entry, &features[i]))
			{
				while (++i < count && (features[i].kind == FEATURE_DEPENDS ||
									   features[i].kind == FEATURE_SDEPEND))
				{
					if (plugin_feature_matches(&features[i], dep))
					{
						enumerator->destroy(enumerator);
						return TRUE;
					}
				}
			}
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

/**
 * Load plugin features in correct order
 */
static int load_features(private_plugin_loader_t *this, bool soft, bool report)
{
	enumerator_t *enumerator;
	plugin_feature_t *feature, *reg;
	plugin_entry_t *entry;
	int count, i, loaded = 0;

	enumerator = this->plugins->create_enumerator(this->plugins);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->plugin->get_features)
		{	/* feature interface not supported */
			continue;
		}
		reg = NULL;
		count = entry->plugin->get_features(entry->plugin, &feature);
		for (i = 0; i < count; i++)
		{
			switch (feature->kind)
			{
				case FEATURE_PROVIDE:
					if (!feature_loaded(this, entry, feature) &&
						!feature_failed(this, entry, feature) &&
						dependencies_satisfied(this, entry, soft, report,
											   feature, count - i))
					{
						if (plugin_feature_load(entry->plugin, feature, reg))
						{
							entry->loaded->insert_last(entry->loaded, feature);
							loaded++;
						}
						else
						{
							entry->failed->insert_last(entry->failed, feature);
						}
					}
					break;
				case FEATURE_REGISTER:
				case FEATURE_CALLBACK:
					reg = feature;
					break;
				default:
					break;
			}
			feature++;
		}
	}
	enumerator->destroy(enumerator);
	return loaded;
}

/**
 * Try to unload plugin features on which is not depended anymore
 */
static int unload_features(private_plugin_loader_t *this, plugin_entry_t *entry)
{
	plugin_feature_t *feature, *reg = NULL;
	int count, i, unloaded = 0;

	count = entry->plugin->get_features(entry->plugin, &feature);
	for (i = 0; i < count; i++)
	{
		switch (feature->kind)
		{
			case FEATURE_PROVIDE:
				if (feature_loaded(this, entry, feature) &&
					!dependency_required(this, feature) &&
					plugin_feature_unload(entry->plugin, feature, reg))
				{
					entry->loaded->remove(entry->loaded, feature, NULL);
					unloaded++;
				}
				break;
			case FEATURE_REGISTER:
			case FEATURE_CALLBACK:
				reg = feature;
				break;
			default:
				break;
		}
		feature++;
	}
	return unloaded;
}

/**
 * Remove plugins that we were not able to load any features from.
 */
static void purge_plugins(private_plugin_loader_t *this)
{
	enumerator_t *enumerator;
	plugin_entry_t *entry;

	enumerator = this->plugins->create_enumerator(this->plugins);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->plugin->get_features)
		{	/* feature interface not supported */
			continue;
		}
		if (!entry->loaded->get_count(entry->loaded))
		{
			this->plugins->remove_at(this->plugins, enumerator);
			plugin_entry_destroy(entry);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(plugin_loader_t, load_plugins, bool,
	private_plugin_loader_t *this, char *path, char *list)
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
		bool critical = FALSE;
		char file[PATH_MAX];
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
		if (snprintf(file, sizeof(file), "%s/libstrongswan-%s.so",
					 path, token) >= sizeof(file))
		{
			return FALSE;
		}
		if (!load_plugin(this, token, file) && critical)
		{
			critical_failed = TRUE;
			DBG1(DBG_LIB, "loading critical plugin '%s' failed", token);
		}
		free(token);
		/* TODO: we currently load features after each plugin is loaded. This
		 * will not be necessary once we have features support in all plugins.
		 */
		while (load_features(this, TRUE, FALSE))
		{
			/* try load new features until we don't get new ones */
		}
	}
	enumerator->destroy(enumerator);
	if (!critical_failed)
	{
		while (load_features(this, FALSE, FALSE))
		{
			/* enforce loading features, ignoring soft dependencies */
		}
		/* report missing dependencies */
		load_features(this, FALSE, TRUE);
		/* unload plugins that we were not able to load any features for */
		purge_plugins(this);
	}
	if (!critical_failed)
	{
		free(this->loaded_plugins);
		this->loaded_plugins = loaded_plugins_list(this);
	}
	return !critical_failed;
}

METHOD(plugin_loader_t, unload, void,
	private_plugin_loader_t *this)
{
	enumerator_t *enumerator;
	plugin_entry_t *entry;
	linked_list_t *list;

	/* unload plugins in reverse order, for those not supporting features */
	list = linked_list_create();
	while (this->plugins->remove_last(this->plugins, (void**)&entry) == SUCCESS)
	{
		list->insert_last(list, entry);
	}
	while (list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		this->plugins->insert_first(this->plugins, entry);
	}
	list->destroy(list);
	while (this->plugins->get_count(this->plugins))
	{
		enumerator = this->plugins->create_enumerator(this->plugins);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->plugin->get_features)
			{	/* supports features */
				while (unload_features(this, entry));
			}
			if (entry->loaded->get_count(entry->loaded) == 0)
			{
				if (lib->leak_detective)
				{	/* keep handle to report leaks properly */
					entry->handle = NULL;
				}
				this->plugins->remove_at(this->plugins, enumerator);
				plugin_entry_destroy(entry);
			}
		}
		enumerator->destroy(enumerator);
	}
	free(this->loaded_plugins);
	this->loaded_plugins = NULL;
}

/**
 * Reload a plugin by name, NULL for all
 */
static u_int reload_by_name(private_plugin_loader_t *this, char *name)
{
	u_int reloaded = 0;
	enumerator_t *enumerator;
	plugin_t *plugin;

	enumerator = create_plugin_enumerator(this);
	while (enumerator->enumerate(enumerator, &plugin, NULL))
	{
		if (name == NULL || streq(name, plugin->get_name(plugin)))
		{
			if (plugin->reload && plugin->reload(plugin))
			{
				DBG2(DBG_LIB, "reloaded configuration of '%s' plugin",
					 plugin->get_name(plugin));
				reloaded++;
			}
		}
	}
	enumerator->destroy(enumerator);
	return reloaded;
}

METHOD(plugin_loader_t, reload, u_int,
	private_plugin_loader_t *this, char *list)
{
	u_int reloaded = 0;
	enumerator_t *enumerator;
	char *name;

	if (list == NULL)
	{
		return reload_by_name(this, NULL);
	}
	enumerator = enumerator_create_token(list, " ", "");
	while (enumerator->enumerate(enumerator, &name))
	{
		reloaded += reload_by_name(this, name);
	}
	enumerator->destroy(enumerator);
	return reloaded;
}

METHOD(plugin_loader_t, loaded_plugins, char*,
	private_plugin_loader_t *this)
{
	return this->loaded_plugins ?: "";
}

METHOD(plugin_loader_t, destroy, void,
	private_plugin_loader_t *this)
{
	unload(this);
	this->plugins->destroy(this->plugins);
	free(this->loaded_plugins);
	free(this);
}

/*
 * see header file
 */
plugin_loader_t *plugin_loader_create()
{
	private_plugin_loader_t *this;

	INIT(this,
		.public = {
			.load = _load_plugins,
			.reload = _reload,
			.unload = _unload,
			.create_plugin_enumerator = _create_plugin_enumerator,
			.loaded_plugins = _loaded_plugins,
			.destroy = _destroy,
		},
		.plugins = linked_list_create(),
	);

	return &this->public;
}

