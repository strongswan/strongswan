/**
 * @file backend_manager.c
 * 
 * @brief Implementation of backend_manager_t.
 * 
 */

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

#include "backend_manager.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <daemon.h>
#include <utils/linked_list.h>
#include <config/backends/writeable_backend.h>


typedef struct private_backend_manager_t private_backend_manager_t;

/**
 * Private data of an backend_manager_t object.
 */
struct private_backend_manager_t {

	/**
	 * Public part of backend_manager_t object.
	 */
	backend_manager_t public;
	
	/**
	 * list of registered backends
	 */
	linked_list_t *backends;
	
	/**
	 * Additional list of writable backends.
	 */
	linked_list_t *writeable;
	
	/**
	 * List of dlopen() handles we used to open backends
	 */
	linked_list_t *handles;
};

/**
 * implements backend_manager_t.get_ike_cfg.
 */
static ike_cfg_t *get_ike_cfg(private_backend_manager_t *this, 
							  host_t *my_host, host_t *other_host)
{
	backend_t *backend;
	ike_cfg_t *config = NULL;
	iterator_t *iterator = this->backends->create_iterator(this->backends, TRUE);
	while (config == NULL && iterator->iterate(iterator, (void**)&backend))
	{
		config = backend->get_ike_cfg(backend, my_host, other_host);
	}
	iterator->destroy(iterator);
	return config;
}

/**
 * implements backend_manager_t.get_peer_cfg.
 */			
static peer_cfg_t *get_peer_cfg(private_backend_manager_t *this,
								identification_t *my_id, identification_t *other_id,
								ca_info_t *other_ca_info)
{
	backend_t *backend;
	peer_cfg_t *config = NULL;
	iterator_t *iterator = this->backends->create_iterator(this->backends, TRUE);
	while (config == NULL && iterator->iterate(iterator, (void**)&backend))
	{
		config = backend->get_peer_cfg(backend, my_id, other_id, other_ca_info);
	}
	iterator->destroy(iterator);
	return config;
}

/**
 * implements backend_manager_t.get_peer_cfg_by_name.
 */			
static peer_cfg_t *get_peer_cfg_by_name(private_backend_manager_t *this, char *name)
{
	backend_t *backend;
	peer_cfg_t *config = NULL;
	iterator_t *iterator = this->backends->create_iterator(this->backends, TRUE);
	while (config == NULL && iterator->iterate(iterator, (void**)&backend))
	{
		config = backend->get_peer_cfg_by_name(backend, name);
	}
	iterator->destroy(iterator);
	return config;
}

/**
 * implements backend_manager_t.add_peer_cfg.
 */	
static void add_peer_cfg(private_backend_manager_t *this, peer_cfg_t *config)
{
	writeable_backend_t *backend;
	
	if (this->writeable->get_first(this->writeable, (void**)&backend) == SUCCESS)
	{
		backend->add_cfg(backend, config);
	}
}

/**
 * implements backend_manager_t.create_iterator.
 */	
static iterator_t* create_iterator(private_backend_manager_t *this)
{
	writeable_backend_t *backend;
	
	if (this->writeable->get_first(this->writeable, (void**)&backend) == SUCCESS)
	{
		return backend->create_iterator(backend);
	}
	/* give out an empty iterator if we have no writable backend*/
	return this->writeable->create_iterator(this->writeable, TRUE);
}

/**
 * load the configuration backend modules
 */
static void load_backends(private_backend_manager_t *this)
{
	struct dirent* entry;
	DIR* dir;

	dir = opendir(IPSEC_BACKENDDIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening backend modules directory "IPSEC_BACKENDDIR);
		return;
	}
	
	DBG1(DBG_CFG, "loading backend modules from '"IPSEC_BACKENDDIR"'");

	while ((entry = readdir(dir)) != NULL)
	{
		char file[256];
		backend_t *backend;
		backend_constructor_t constructor;
		void *handle;
		char *ending;
		
		snprintf(file, sizeof(file), IPSEC_BACKENDDIR"/%s", entry->d_name);
		
		ending = entry->d_name + strlen(entry->d_name) - 3;
		if (ending <= entry->d_name || !streq(ending, ".so"))
		{
			/* skip anything which does not look like a library */
			DBG2(DBG_CFG, "  skipping %s, doesn't look like a library",
				 entry->d_name);
			continue;
		}
		/* try to load the library */
		handle = dlopen(file, RTLD_LAZY);
		if (handle == NULL)
		{
			DBG1(DBG_CFG, "  opening backend module %s failed: %s",
				 entry->d_name, dlerror());
			continue;
		}
		constructor = dlsym(handle, "backend_create");
		if (constructor == NULL)
		{
			DBG1(DBG_CFG, "  backend module %s has no backend_create() "
				 "function, skipped", entry->d_name);
			dlclose(handle);
			continue;
		}
		
		backend = constructor();
		if (backend == NULL)
		{
			DBG1(DBG_CFG, "  unable to create instance of backend "
				 "module %s, skipped", entry->d_name);
			dlclose(handle);
			continue;
		}
		DBG1(DBG_CFG, "  loaded backend module successfully from %s", entry->d_name);
		this->backends->insert_last(this->backends, backend);
		if (backend->is_writeable(backend))
		{
			this->writeable->insert_last(this->writeable, backend);
		}
		this->handles->insert_last(this->handles, handle);
	}
	closedir(dir);
}

/**
 * Implementation of backend_manager_t.destroy.
 */
static void destroy(private_backend_manager_t *this)
{
	this->backends->destroy_offset(this->backends, offsetof(backend_t, destroy));
	this->writeable->destroy(this->writeable);
	this->handles->destroy_function(this->handles, (void*)dlclose);
	free(this);
}

/*
 * Described in header-file
 */
backend_manager_t *backend_manager_create()
{
	private_backend_manager_t *this = malloc_thing(private_backend_manager_t);
	
	this->public.get_ike_cfg = (ike_cfg_t* (*)(backend_manager_t*, host_t*, host_t*))get_ike_cfg;
	this->public.get_peer_cfg = (peer_cfg_t* (*)(backend_manager_t*,identification_t*,identification_t*,ca_info_t*))get_peer_cfg;
	this->public.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_manager_t*,char*))get_peer_cfg_by_name;
	this->public.add_peer_cfg = (void (*)(backend_manager_t*,peer_cfg_t*))add_peer_cfg;
	this->public.create_iterator = (iterator_t* (*)(backend_manager_t*))create_iterator;
	this->public.destroy = (void (*)(backend_manager_t*))destroy;
	
	this->backends = linked_list_create();
	this->writeable = linked_list_create();
	this->handles = linked_list_create();
	
	load_backends(this);
	
	return &this->public;
}

