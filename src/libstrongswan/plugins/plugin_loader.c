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
 * Check if dependencies are satisfied
 */
static bool dependencies_satisfied(private_plugin_loader_t *this, char *name,
				bool soft, bool report, plugin_feature_t *features, int count)
{
	int i;

	/* first entry is provided feature, followed by dependencies */
	for (i = 1; i < count; i++)
	{
		enumerator_t *entries, *loaded;
		plugin_feature_t *feature;
		plugin_entry_t *entry;
		bool found = FALSE;

		if (features[i].kind != FEATURE_DEPENDS &&
			features[i].kind != FEATURE_SDEPEND)
		{	/* end of dependencies */
			break;
		}
		entries = this->plugins->create_enumerator(this->plugins);
		while (entries->enumerate(entries, &entry))
		{
			loaded = entry->loaded->create_enumerator(entry->loaded);
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
				char *provide, *depend;

				provide = plugin_feature_get_string(&features[0]);
				depend = plugin_feature_get_string(&features[i]);
				DBG1(DBG_LIB, "feature %s in '%s' plugin has unsatisfied "
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
 * Load a plugin feature
 */
static bool load_feature(private_plugin_loader_t *this, plugin_entry_t *entry,
				char *name, plugin_feature_t *feature, plugin_feature_t *reg)
{
	char *str;

	str = plugin_feature_get_string(feature);
	switch (feature->type)
	{
		case FEATURE_CRYPTER:
		case FEATURE_AEAD:
		case FEATURE_SIGNER:
		case FEATURE_HASHER:
		case FEATURE_PRF:
		case FEATURE_DH:
		case FEATURE_RNG:
		case FEATURE_PRIVKEY:
		case FEATURE_PRIVKEY_GEN:
		case FEATURE_PUBKEY:
		case FEATURE_CERT_DECODE:
		case FEATURE_CERT_ENCODE:
		case FEATURE_DATABASE:
		case FEATURE_FETCHER:
			/* require a registration function */
			if (!reg ||
				(reg->kind == FEATURE_REGISTER && reg->type != feature->type))
			{
				DBG1(DBG_LIB, "loading '%s' plugin feature %s failed: "
					 "invalid registration function", name, str);
				free(str);
				return FALSE;
			}
			break;
		default:
			break;
	}
	if (reg && reg->kind == FEATURE_CALLBACK)
	{
		if (!reg->arg.cb.f(entry->plugin, feature, TRUE, reg->arg.cb.data))
		{
			DBG1(DBG_LIB, "loading '%s' plugin feature %s with callback failed",
				 name, str);
			free(str);
			return FALSE;
		}
	}
	else
	{
		switch (feature->type)
		{
			case FEATURE_CRYPTER:
				lib->crypto->add_crypter(lib->crypto, feature->arg.crypter.alg,
									name, reg->arg.reg.f);
				break;
			case FEATURE_AEAD:
				lib->crypto->add_aead(lib->crypto, feature->arg.aead.alg,
									name, reg->arg.reg.f);
				break;
			case FEATURE_SIGNER:
				lib->crypto->add_signer(lib->crypto, feature->arg.signer,
									name, reg->arg.reg.f);
				break;
			case FEATURE_HASHER:
				lib->crypto->add_hasher(lib->crypto, feature->arg.hasher,
									name, reg->arg.reg.f);
				break;
			case FEATURE_PRF:
				lib->crypto->add_prf(lib->crypto, feature->arg.prf,
									name, reg->arg.reg.f);
				break;
			case FEATURE_DH:
				lib->crypto->add_dh(lib->crypto, feature->arg.dh_group,
									name, reg->arg.reg.f);
				break;
			case FEATURE_RNG:
				lib->crypto->add_rng(lib->crypto, feature->arg.rng_quality,
									name, reg->arg.reg.f);
				break;
			case FEATURE_PRIVKEY:
			case FEATURE_PRIVKEY_GEN:
				lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY,
									feature->arg.privkey, reg->arg.reg.final,
									reg->arg.reg.f);
				break;
			case FEATURE_PUBKEY:
				lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY,
									feature->arg.pubkey, reg->arg.reg.final,
									reg->arg.reg.f);
				break;
			case FEATURE_CERT_DECODE:
			case FEATURE_CERT_ENCODE:
				lib->creds->add_builder(lib->creds, CRED_CERTIFICATE,
									feature->arg.cert, reg->arg.reg.final,
									reg->arg.reg.f);
				break;
			case FEATURE_DATABASE:
				lib->db->add_database(lib->db, reg->arg.reg.f);
				break;
			case FEATURE_FETCHER:
				lib->fetcher->add_fetcher(lib->fetcher, reg->arg.reg.f,
										  feature->arg.fetcher);
				break;
			default:
				break;
		}
	}
	DBG2(DBG_LIB, "loaded '%s' plugin feature %s", name, str);
	free(str);
	entry->loaded->insert_last(entry->loaded, feature);
	return TRUE;
}

/**
 * Load plugin features in correct order
 */
static int load_features(private_plugin_loader_t *this, bool soft, bool report)
{
	enumerator_t *enumerator;
	plugin_feature_t *features, *reg = NULL;
	plugin_entry_t *entry;
	int count, i, loaded = 0;
	char *name;

	enumerator = this->plugins->create_enumerator(this->plugins);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->plugin->get_features)
		{	/* feature interface not supported */
			continue;
		}
		name = entry->plugin->get_name(entry->plugin);
		count = entry->plugin->get_features(entry->plugin, &features);
		for (i = 0; i < count; i++)
		{
			switch (features[i].kind)
			{
				case FEATURE_PROVIDE:
					if (!feature_loaded(this, entry, &features[i]) &&
						dependencies_satisfied(this, name, soft, report,
											   &features[i], count - i) &&
						load_feature(this, entry, name, &features[i], reg))
					{
						loaded++;
					}
					break;
				case FEATURE_REGISTER:
				case FEATURE_CALLBACK:
					reg = &features[i];
					break;
				default:
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
	return loaded;
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
			return NULL;
		}
		if (!load_plugin(this, token, file) && critical)
		{
			critical_failed = TRUE;
			DBG1(DBG_LIB, "loading critical plugin '%s' failed", token);
		}
		free(token);
	}
	enumerator->destroy(enumerator);
	if (!critical_failed)
	{
		while (load_features(this, TRUE, FALSE))
		{
			/* try load new features until we don't get new ones */
		}
		while (load_features(this, FALSE, FALSE))
		{
			/* second round, ignoring soft dependencies */
		}
		/* report missing dependencies */
		load_features(this, FALSE, TRUE);
		/* unload plugins that we were not able to load any features for */
		purge_plugins(this);
	}
	return !critical_failed;
}

METHOD(plugin_loader_t, unload, void,
	private_plugin_loader_t *this)
{
	plugin_entry_t *entry;

	/* unload plugins in reverse order */
	while (this->plugins->remove_last(this->plugins,
									   (void**)&entry) == SUCCESS)
	{
		if (lib->leak_detective)
		{	/* keep handle to report leaks properly */
			entry->handle = NULL;
		}
		plugin_entry_destroy(entry);
	}
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

METHOD(plugin_loader_t, destroy, void,
	private_plugin_loader_t *this)
{
	unload(this);
	this->plugins->destroy(this->plugins);
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
			.destroy = _destroy,
		},
		.plugins = linked_list_create(),
	);

	return &this->public;
}

