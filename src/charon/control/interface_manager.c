/**
 * @file interface_manager.c
 * 
 * @brief Implementation of interface_manager_t.
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

#include "interface_manager.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <daemon.h>
#include <library.h>
#include <control/interfaces/interface.h>
#include <processing/job_queue.h>
#include <processing/jobs/initiate_job.h>


typedef struct private_interface_manager_t private_interface_manager_t;

/**
 * Private data of an stroke_t object.
 */
struct private_interface_manager_t {

	/**
	 * Public part of stroke_t object.
	 */
	interface_manager_t public;
	
	/**
	 * a list of all loaded interfaces
	 */
	linked_list_t *interfaces;
	
	/**
	 * dlopen() handles of interfaces
	 */
	linked_list_t *handles;
};
	
/**
 * Implementation of interface_manager_t.initiate.
 */
static status_t initiate(private_interface_manager_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 bool(*cb)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),
						 void *param)
{
	ike_sa_t *ours = NULL;
	job_t *job;
	status_t retval;
	
	charon->bus->set_listen_state(charon->bus, TRUE);
	
	job = (job_t*)initiate_job_create(peer_cfg, child_cfg);
	charon->job_queue->add(charon->job_queue, job);
	
	while (TRUE)
	{
		level_t level;
		signal_t signal;
		int thread;
		ike_sa_t *ike_sa;
		char* format;
		va_list args;
		
		signal = charon->bus->listen(charon->bus, &level, &thread, 
									 &ike_sa, &format, &args);
		
		if (cb && (ike_sa == ours || ours == NULL))
		{
			if (!cb(param, signal, level, ike_sa, format, args))
			{
				charon->bus->set_listen_state(charon->bus, FALSE);
				return NEED_MORE;
			}
		}
		
		switch (signal)
		{
			case CHILD_UP_SUCCESS:
				if (ike_sa == ours)
				{
					retval = SUCCESS;
					break;
				}
				continue;
			case CHILD_UP_FAILED:
			case IKE_UP_FAILED:
				if (ike_sa == ours)
				{
					retval = FAILED;
					break;
				}
				continue;
			case CHILD_UP_START:
			case IKE_UP_START:
				if (ours == NULL)
				{
					ours = ike_sa;
				}
				continue;
			default:
				continue;
		}
		break;
	}
	charon->bus->set_listen_state(charon->bus, FALSE);
	return retval;
}

/**
 * load the control interface modules
 */
static void load_interfaces(private_interface_manager_t *this)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	
	if (stat(IPSEC_INTERFACEDIR, &stb) == -1 || !(stb.st_mode & S_IFDIR))
	{
		DBG1(DBG_CFG, "error opening interface modules directory "IPSEC_INTERFACEDIR);
		return;
	}

	dir = opendir(IPSEC_INTERFACEDIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening interface modules directory "IPSEC_INTERFACEDIR);
		return;
	}
	
	DBG1(DBG_CFG, "loading control interface modules from '"IPSEC_INTERFACEDIR"'");

	while ((entry = readdir(dir)) != NULL)
	{
		char file[256];
		interface_t *interface;
		interface_constructor_t constructor;
		void *handle;
		char *ending;
		
		snprintf(file, sizeof(file), IPSEC_INTERFACEDIR"/%s", entry->d_name);
		
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
		/* try to load the library */
		handle = dlopen(file, RTLD_LAZY);
		if (handle == NULL)
		{
			DBG1(DBG_CFG, "  opening control interface module %s failed: %s",
				 entry->d_name, dlerror());
			continue;
		}
		constructor = dlsym(handle, "interface_create");
		if (constructor == NULL)
		{
			DBG1(DBG_CFG, "  interface module %s has no interface_create() "
				 "function, skipped", entry->d_name);
			dlclose(handle);
			continue;
		}
		
		interface = constructor();
		if (interface == NULL)
		{
			DBG1(DBG_CFG, "  unable to create instance of interface "
				 "module %s, skipped", entry->d_name);
			dlclose(handle);
			continue;
		}
		DBG1(DBG_CFG, "  loaded control interface module successfully from %s", entry->d_name);
		this->interfaces->insert_last(this->interfaces, interface);
		this->handles->insert_last(this->handles, handle);
	}
	closedir(dir);
}


/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_interface_manager_t *this)
{
	this->interfaces->destroy_offset(this->interfaces, offsetof(interface_t, destroy));
	this->handles->destroy_function(this->handles, (void*)dlclose);
	free(this);
}

/*
 * Described in header-file
 */
interface_manager_t *interface_manager_create(void)
{
	private_interface_manager_t *this = malloc_thing(private_interface_manager_t);
	
	this->public.initiate = (status_t(*)(interface_manager_t*,peer_cfg_t*,child_cfg_t*,bool(*)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),void*))initiate;
	this->public.destroy = (void (*)(interface_manager_t*))destroy;
	
	this->interfaces = linked_list_create();
	this->handles = linked_list_create();
	
	load_interfaces(this);
	
	return &this->public;
}

