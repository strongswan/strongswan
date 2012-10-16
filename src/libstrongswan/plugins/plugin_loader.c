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

#include <utils/debug.h>
#include <library.h>
#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <plugins/plugin.h>
#include <utils/integrity_checker.h>

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
	 * Hashtable for loaded features, as plugin_feature_t
	 */
	hashtable_t *loaded_features;

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
	 * TRUE, if the plugin is marked as critical
	 */
	bool critical;

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
 * Wrapper for static plugin features
 */
typedef struct {

	/**
	 * Implements plugin_t interface
	 */
	plugin_t public;

	/**
	 * Name of the module registering these features
	 */
	char *name;

	/**
	 * Static plugin features
	 */
	plugin_feature_t *features;

	/**
	 * Number of plugin features
	 */
	int count;

} static_features_t;

METHOD(plugin_t, get_static_name, char*,
	static_features_t *this)
{
	return this->name;
}

METHOD(plugin_t, get_static_features, int,
	static_features_t *this, plugin_feature_t *features[])
{
	*features = this->features;
	return this->count;
}

METHOD(plugin_t, static_destroy, void,
	static_features_t *this)
{
	free(this->features);
	free(this->name);
	free(this);
}

/**
 * Create a wrapper around static plugin features.
 */
static plugin_t *static_features_create(const char *name,
										plugin_feature_t features[], int count)
{
	static_features_t *this;

	INIT(this,
		.public = {
			.get_name = _get_static_name,
			.get_features = _get_static_features,
			.destroy = _static_destroy,
		},
		.name = strdup(name),
		.features = calloc(count, sizeof(plugin_feature_t)),
		.count = count,
	);

	memcpy(this->features, features, sizeof(plugin_feature_t) * count);

	return &this->public;
}

/**
 * Compare function for hashtable of loaded features.
 */
static bool plugin_feature_equals(plugin_feature_t *a, plugin_feature_t *b)
{
	return a == b;
}

/**
 * create a plugin
 * returns: NOT_FOUND, if the constructor was not found
 *          FAILED, if the plugin could not be constructed
 */
static status_t create_plugin(private_plugin_loader_t *this, void *handle,
							  char *name, bool integrity, bool critical,
							  plugin_entry_t **entry)
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
		.critical = critical,
		.loaded = linked_list_create(),
		.failed = linked_list_create(),
	);
	DBG2(DBG_LIB, "plugin '%s': loaded successfully", name);
	return SUCCESS;
}

/**
 * load a single plugin
 */
static bool load_plugin(private_plugin_loader_t *this, char *name, char *file,
						bool critical)
{
	plugin_entry_t *entry;
	void *handle;

	switch (create_plugin(this, RTLD_DEFAULT, name, FALSE, critical, &entry))
	{
		case SUCCESS:
			this->plugins->insert_last(this->plugins, entry);
			return TRUE;
		case NOT_FOUND:
			if (file)
			{	/* try to load the plugin from a file */
				break;
			}
			/* fall-through */
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
	if (create_plugin(this, handle, name, TRUE, critical, &entry) != SUCCESS)
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
		plugin_feature_t *found;

		if (features[i].kind != FEATURE_DEPENDS &&
			features[i].kind != FEATURE_SDEPEND)
		{	/* end of dependencies */
			break;
		}
		found = this->loaded_features->get_match(this->loaded_features,
					&features[i], (hashtable_equals_t)plugin_feature_matches);
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
			if (&features[i] != dep &&
				feature_loaded(this, entry, &features[i]))
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
							this->loaded_features->put(this->loaded_features,
													   feature, feature);
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
		if (loaded && !report)
		{	/* got new feature, restart from beginning of list */
			break;
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
					this->loaded_features->remove(this->loaded_features,
												  feature);
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
 * Check that we have all features loaded for critical plugins
 */
static bool missing_critical_features(private_plugin_loader_t *this)
{
	enumerator_t *enumerator;
	plugin_entry_t *entry;
	bool critical_failed = FALSE;

	enumerator = this->plugins->create_enumerator(this->plugins);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->plugin->get_features)
		{	/* feature interface not supported */
			continue;
		}
		if (entry->critical)
		{
			plugin_feature_t *feature;
			char *name, *provide;
			int count, i, failed = 0;

			name = entry->plugin->get_name(entry->plugin);
			count = entry->plugin->get_features(entry->plugin, &feature);
			for (i = 0; i < count; i++, feature++)
			{
				if (feature->kind == FEATURE_PROVIDE &&
					!feature_loaded(this, entry, feature))
				{
					provide = plugin_feature_get_string(feature);
					DBG2(DBG_LIB, "  failed to load %s in critical plugin '%s'",
						 provide, name);
					free(provide);
					failed++;
				}
			}
			if (failed)
			{
				DBG1(DBG_LIB, "failed to load %d feature%s in critical plugin "
					 "'%s'", failed, failed > 1 ? "s" : "", name);
				critical_failed = TRUE;
			}
		}
	}
	enumerator->destroy(enumerator);

	return critical_failed;
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

METHOD(plugin_loader_t, add_static_features, void,
	private_plugin_loader_t *this, const char *name,
	plugin_feature_t features[], int count, bool critical)
{
	plugin_entry_t *entry;
	plugin_t *plugin;

	plugin = static_features_create(name, features, count);

	INIT(entry,
		.plugin = plugin,
		.critical = critical,
		.loaded = linked_list_create(),
		.failed = linked_list_create(),
	);
	this->plugins->insert_last(this->plugins, entry);
}

METHOD(plugin_loader_t, load_plugins, bool,
	private_plugin_loader_t *this, char *path, char *list)
{
	enumerator_t *enumerator;
	char *token;
	bool critical_failed = FALSE;

#ifdef PLUGINDIR
	if (path == NULL)
	{
		path = PLUGINDIR;
	}
#endif /* PLUGINDIR */

	enumerator = enumerator_create_token(list, " ", " ");
	while (!critical_failed && enumerator->enumerate(enumerator, &token))
	{
		bool critical = FALSE;
		char buf[PATH_MAX], *file = NULL;
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
		if (path)
		{
			if (snprintf(buf, sizeof(buf), "%s/libstrongswan-%s.so",
						 path, token) >= sizeof(buf))
			{
				return FALSE;
			}
			file = buf;
		}
		if (!load_plugin(this, token, file, critical) && critical)
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
		/* check for unloaded features provided by critical plugins */
		critical_failed = missing_critical_features(this);
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
	this->loaded_features->destroy(this->loaded_features);
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
			.add_static_features = _add_static_features,
			.load = _load_plugins,
			.reload = _reload,
			.unload = _unload,
			.create_plugin_enumerator = _create_plugin_enumerator,
			.loaded_plugins = _loaded_plugins,
			.destroy = _destroy,
		},
		.plugins = linked_list_create(),
		.loaded_features = hashtable_create(
								(hashtable_hash_t)plugin_feature_hash,
								(hashtable_equals_t)plugin_feature_equals, 64),
	);

	return &this->public;
}

