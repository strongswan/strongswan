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


typedef struct private_interface_manager_t private_interface_manager_t;
typedef struct interface_bus_listener_t interface_bus_listener_t;

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
 * helper struct to map bus listener callbacks to interface callbacks
 */
struct interface_bus_listener_t {

	/**
	 * bus listener callback function (called)
	 */
	bus_listener_t listener;
	
	/**
	 * IKE_SA to use for message filtering
	 */
	ike_sa_t *ike_sa;
	
	/**
	 *  interface callback (listener gets redirected to here)
	 */
	interface_manager_cb_t callback;
	
	/**
	 * user parameter to pass to callback
	 */
	void *param;
	
	/**
	 * caller has cancelled its listening subscription
	 */
	bool cancelled;
};

/**
 * Implementation of interface_manager_t.create_ike_sa_iterator.
 */
static iterator_t* create_ike_sa_iterator(interface_manager_t *this)
{
	return charon->ike_sa_manager->create_iterator(charon->ike_sa_manager);
}

/**
 * listener function for initiate
 */
static bool initiate_listener(interface_bus_listener_t *this, signal_t signal,
							  level_t level, int thread, ike_sa_t *ike_sa,
							  char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			this->cancelled = TRUE;
			return FALSE;
		}
		switch (signal)
		{
			case IKE_UP_FAILED:
			case CHILD_UP_FAILED:
			case CHILD_UP_SUCCESS:
			{
				return FALSE;
			}
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * listener function for terminate_ike
 */
static bool terminate_ike_listener(interface_bus_listener_t *this, signal_t signal,
								   level_t level, int thread, ike_sa_t *ike_sa,
								   char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			this->cancelled = TRUE;
			return FALSE;
		}
		switch (signal)
		{
			case IKE_DOWN_FAILED:
			case IKE_DOWN_SUCCESS:
			{
				return FALSE;
			}
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * listener function for terminate_child
 */
static bool terminate_child_listener(interface_bus_listener_t *this, signal_t signal,
									 level_t level, int thread, ike_sa_t *ike_sa,
									 char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			this->cancelled = TRUE;
			return FALSE;
		}
		switch (signal)
		{
			case IKE_DOWN_FAILED:
			case IKE_DOWN_SUCCESS:
			case CHILD_DOWN_FAILED:
			case CHILD_DOWN_SUCCESS:
			{
				return FALSE;
			}
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * Implementation of interface_manager_t.initiate.
 */
static status_t initiate(private_interface_manager_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 interface_manager_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	ike_cfg_t *ike_cfg;
	status_t retval = FAILED;
	interface_bus_listener_t listener;
	
	ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
	ike_sa = charon->ike_sa_manager->checkout_by_peer(charon->ike_sa_manager,
				ike_cfg->get_my_host(ike_cfg), ike_cfg->get_other_host(ike_cfg),
				peer_cfg->get_my_id(peer_cfg), peer_cfg->get_other_id(peer_cfg));

	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}

	listener.listener.signal = (void*)initiate_listener;
	listener.callback = callback;
	listener.ike_sa = ike_sa;
	listener.param = param;
	listener.cancelled = FALSE;

	/* we listen passively to catch the signals we are raising in 
	 * ike_sa->delete(). */
	if (callback)
	{
		charon->bus->add_listener(charon->bus, &listener.listener);
	}
	charon->bus->set_listen_state(charon->bus, TRUE);
	if (ike_sa->initiate(ike_sa, child_cfg) != SUCCESS)
	{
		charon->bus->set_listen_state(charon->bus, FALSE);
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
		return FAILED;
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	
	/* wait until we get a result */
	while (TRUE)
	{
		level_t level;
		signal_t signal;
		int thread;
		ike_sa_t *current;
		char* format;
		va_list args;
		
		/* stop listening if the passive listener returned FALSE */
		if (listener.cancelled)
		{
			retval = NEED_MORE;
			break;
		}
		signal = charon->bus->listen(charon->bus, &level, &thread, 
									 &current, &format, &args);
		/* ike_sa is a valid pointer until we get one of the signals */
		if (ike_sa == current)
		{
			switch (signal)
			{
				case CHILD_UP_SUCCESS:
					retval = SUCCESS;
				case CHILD_UP_FAILED:
				case IKE_UP_FAILED:
					break;
				default:
					continue;
			}
			break;
		}
	}
	charon->bus->set_listen_state(charon->bus, FALSE);
	return retval;
}

/**
 * Implementation of interface_manager_t.terminate_ike.
 */
static status_t terminate_ike(interface_manager_t *this, u_int32_t unique_id, 
							  interface_manager_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	status_t status = FAILED;;
	interface_bus_listener_t listener;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													unique_id, FALSE);							
	if (ike_sa == NULL)
	{
		return NOT_FOUND;
	}
	
	/* we listen passively to catch the signals we are raising in 
	 * ike_sa->delete(). */
	listener.listener.signal = (void*)terminate_ike_listener;
	listener.callback = callback;
	listener.ike_sa = ike_sa;
	listener.param = param;
	listener.cancelled = FALSE;
	if (callback)
	{
		charon->bus->add_listener(charon->bus, &listener.listener);
	}
	charon->bus->set_listen_state(charon->bus, TRUE);
	status = ike_sa->delete(ike_sa);
	if (status == DESTROY_ME)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		
		/* wait until IKE_SA is cleanly deleted using a delete message */
		while (TRUE)
		{
			level_t level;
			signal_t signal;
			int thread;
			ike_sa_t *current;
			char* format;
			va_list args;
			
			/* stop listening if the passive listener returned FALSE */
			if (listener.cancelled)
			{
				status = NEED_MORE;
				break;
			}
			signal = charon->bus->listen(charon->bus, &level, &thread, 
										 &current, &format, &args);

			/* even if we checked in the IKE_SA, the pointer is valid until
			 * we get an IKE_DOWN_... */
			if (ike_sa == current)
			{
				switch (signal)
				{
					case IKE_DOWN_FAILED:
					case IKE_DOWN_SUCCESS:
					{
						status = SUCCESS;
						break;
					}
					default:
						continue;
				}
				break;
			}
		}
	}
	charon->bus->set_listen_state(charon->bus, FALSE);

	return status;
}

/**
 * Implementation of interface_manager_t.terminate_child.
 */
static status_t terminate_child(interface_manager_t *this, u_int32_t reqid, 
								interface_manager_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	iterator_t *iterator;
	status_t status = FAILED;
	interface_bus_listener_t listener;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													reqid, TRUE);							
	if (ike_sa == NULL)
	{
		return NOT_FOUND;
	}
	
	iterator = ike_sa->create_child_sa_iterator(ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) != CHILD_ROUTED &&
			child_sa->get_reqid(child_sa) == reqid)
		{
			break;
		}
		child_sa = NULL;
	}
	iterator->destroy(iterator);
	
	if (child_sa == NULL)
	{
		return NOT_FOUND;
	}
	
	listener.listener.signal = (void*)terminate_child_listener;
	listener.callback = callback;
	listener.ike_sa = ike_sa;
	listener.param = param;
	listener.cancelled = FALSE;
		
	/* we listen passively to catch the signals we are raising */
	if (callback)
	{
		charon->bus->add_listener(charon->bus, &listener.listener);
	}
	charon->bus->set_listen_state(charon->bus, TRUE);
	status = ike_sa->delete_child_sa(ike_sa, child_sa->get_protocol(child_sa),
									 child_sa->get_spi(child_sa, TRUE));
	if (status == DESTROY_ME)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		
		/* wait until CHILD_SA is cleanly deleted using a delete message */
		while (TRUE)
		{
			level_t level;
			signal_t signal;
			int thread;
			ike_sa_t *current;
			char* format;
			va_list args;
			
			/* stop listening if the passive listener returned FALSE */
			if (listener.cancelled)
			{
				status = NEED_MORE;
				break;
			}
			signal = charon->bus->listen(charon->bus, &level, &thread, 
										 &current, &format, &args);
			/* even if we checked in the IKE_SA, the pointer is valid until
			 * we get an IKE_DOWN_... */
			if (ike_sa == current)
			{
				switch (signal)
				{
					case IKE_DOWN_FAILED:
					case IKE_DOWN_SUCCESS:
					case CHILD_DOWN_FAILED:
					case CHILD_DOWN_SUCCESS:
					{
						status = SUCCESS;
						break;
					}
					default:
						continue;
				}
				break;
			}
		}
	}
	charon->bus->set_listen_state(charon->bus, FALSE);

	return status;
}

/**
 * Implementation of interface_manager_t.route.
 */
static status_t route(interface_manager_t *this,
					  peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
					  interface_manager_cb_t callback, void *param)
{
	return FAILED;
}

/**
 * Implementation of interface_manager_t.unroute.
 */
static status_t unroute(interface_manager_t *this, u_int32_t reqid, 
						interface_manager_cb_t callback, void *param)
{
	return FAILED;
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
	
	this->public.create_ike_sa_iterator = (iterator_t*(*)(interface_manager_t*))create_ike_sa_iterator;
	this->public.initiate = (status_t(*)(interface_manager_t*,peer_cfg_t*,child_cfg_t*,bool(*)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),void*))initiate;
	this->public.terminate_ike = (status_t(*)(interface_manager_t*,u_int32_t,interface_manager_cb_t, void*))terminate_ike;
	this->public.terminate_child = (status_t(*)(interface_manager_t*,u_int32_t,interface_manager_cb_t, void *param))terminate_child;
	this->public.route = (status_t(*)(interface_manager_t*,peer_cfg_t*, child_cfg_t*,interface_manager_cb_t,void*))route;
	this->public.unroute = (status_t(*)(interface_manager_t*,u_int32_t,interface_manager_cb_t,void*))unroute;
	this->public.destroy = (void (*)(interface_manager_t*))destroy;
	
	this->interfaces = linked_list_create();
	this->handles = linked_list_create();
	
	load_interfaces(this);
	
	return &this->public;
}

