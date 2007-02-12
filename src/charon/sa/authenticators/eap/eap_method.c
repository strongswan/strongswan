/**
 * @file eap_method.c
 *
 * @brief Generic constructor for eap_methods.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <error.h>
#include <dlfcn.h>

#include "eap_method.h"

#include <daemon.h>
#include <library.h>
#include <utils/linked_list.h>
#include <utils/identification.h>


ENUM_BEGIN(eap_type_names, EAP_IDENTITY, EAP_TOKEN_CARD,
	"EAP_IDENTITY",
	"EAP_NOTIFICATION",
	"EAP_NAK",
	"EAP_MD5",
	"EAP_ONE_TIME_PASSWORD",
	"EAP_TOKEN_CARD");
ENUM_NEXT(eap_type_names, EAP_AKA, EAP_AKA, EAP_TOKEN_CARD,
	"EAP_AKA");
ENUM_END(eap_type_names, EAP_AKA);

ENUM(eap_code_names, EAP_REQUEST, EAP_FAILURE,
	"EAP_REQUEST",
	"EAP_RESPONSE",
	"EAP_SUCCESS",
	"EAP_FAILURE",
);

ENUM(eap_role_names, EAP_SERVER, EAP_PEER,
	"EAP_SERVER",
	"EAP_PEER",
);


typedef struct module_entry_t module_entry_t;

/**
 * Representation of a loaded module: EAP type, library handle, constructor
 */
struct module_entry_t {
	eap_type_t type;
	void *handle;
	eap_constructor_t constructor;
};

/** List of module_entry_t's */
static linked_list_t *modules = NULL;

/**
 * unload modules at daemon shutdown
 */
void eap_method_unload()
{
	if (modules)
	{
		module_entry_t *entry;
		
		while (modules->remove_last(modules, (void**)&entry) == SUCCESS)
		{
			DBG2(DBG_CFG, "unloaded module for %s", eap_type_names, entry->type);
			dlclose(entry->handle);
			free(entry);
		}
		modules->destroy(modules);
		modules = NULL;
	}
}

/**
 * Load EAP modules at daemon startup
 */
void eap_method_load(char *directory)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	
	eap_method_unload();	
	modules = linked_list_create();
	
	if (stat(directory, &stb) == -1 || !(stb.st_mode & S_IFDIR))
	{
		DBG1(DBG_CFG, "error opening EAP modules directory %s", directory);
		return;
	}
	if (stb.st_uid != 0)
	{
		DBG1(DBG_CFG, "EAP modules directory %s not owned by root, skipped", directory);
		return;
	}
	if (stb.st_mode & S_IWOTH || stb.st_mode & S_IWGRP)
	{
		DBG1(DBG_CFG, "EAP modules directory %s writable by others, skipped", directory);
		return;
	}

	dir = opendir(directory);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening EAP modules directory %s", directory);
		return;
	}
	
	DBG1(DBG_CFG, "loading EAP modules from '%s'", directory);

	while ((entry = readdir(dir)) != NULL)
	{
		char file[256];
		module_entry_t module, *loaded_module;
		eap_method_t *method;
		identification_t *id;
		char *ending;
		
		snprintf(file, sizeof(file), "%s/%s", directory, entry->d_name);
		
		if (stat(file, &stb) == -1 || !(stb.st_mode & S_IFREG))
		{
			DBG2(DBG_CFG, "  skipping %s, doesn't look like a file",
				 entry->d_name);
			continue;
		}
		ending = entry->d_name + strlen(entry->d_name) - 3;
		if (ending <= entry->d_name || !streq(ending, ".so"))
		{
			/* skip anything which does not look like a library */
			DBG2(DBG_CFG, "  skipping %s, doesn't look like a library",
				 entry->d_name);
			continue;
		}
		if (stb.st_uid != 0)
		{
			DBG1(DBG_CFG, "  skipping %s, file is not owned by root", entry->d_name);
			return;
		}
		if (stb.st_mode & S_IWOTH || stb.st_mode & S_IWGRP)
		{
			DBG1(DBG_CFG, "  skipping %s, file is writeable by others", entry->d_name);
			continue;
		}
		
		/* try to load the library */
		module.handle = dlopen(file, RTLD_LAZY);
		if (module.handle == NULL)
		{
			DBG1(DBG_CFG, "  opening EAP module %s failed: %s", entry->d_name,
				 dlerror());
			continue;
		}
		module.constructor = dlsym(module.handle, "eap_create");
		if (module.constructor == NULL)
		{
			DBG1(DBG_CFG, "  EAP module %s has no eap_create() function, skipped",
				entry->d_name);
			dlclose(module.handle);
			continue;
		}
		
		/* get the type implemented in the method, create an instance for it */
		id = identification_create_from_string("john@doe.xyz");
		method = module.constructor(EAP_SERVER, id, id);
		if (method == NULL)
		{
			method = module.constructor(EAP_PEER, id, id);
		}
		id->destroy(id);
		if (method == NULL)
		{
			DBG1(DBG_CFG, "  unable to create instance of EAP method %s, skipped",
				 entry->d_name);
			dlclose(module.handle);
			continue;
		}
		module.type = method->get_type(method);
		method->destroy(method);
		
		DBG1(DBG_CFG, "  loaded EAP method %N successfully from %s",
			 eap_type_names, module.type, entry->d_name);
			 
		loaded_module = malloc_thing(module_entry_t);
		memcpy(loaded_module, &module, sizeof(module));
		modules->insert_last(modules, loaded_module);
	}
	closedir(dir);
}

/*
 * Described in header.
 */
eap_method_t *eap_method_create(eap_type_t type, eap_role_t role,
								identification_t *server,
								identification_t *peer)
{
	eap_method_t *method = NULL;
	iterator_t *iterator;
	module_entry_t *entry;
	
	iterator = modules->create_iterator(modules, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		if (entry->type == type)
		{
			method = entry->constructor(role, server, peer);
			if (method)
			{
				break;
			}
		}
	}
	iterator->destroy(iterator);
	
	if (method == NULL)
	{
		DBG1(DBG_CFG, "no EAP module found for %N %N",
			 eap_type_names, type, eap_role_names, role);
	}
	return method;
}
