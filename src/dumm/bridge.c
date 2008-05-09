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

#include <sys/types.h>
#include <libbridge.h>

#include <debug.h>
#include <utils/linked_list.h>

#include "bridge.h"

typedef struct private_bridge_t private_bridge_t;

struct private_bridge_t {
	/** public interface */
	bridge_t public;
	/** device name */
	char *name;
	/** list of attached interfaces */
	linked_list_t *ifaces;
};

/**
 * defined in iface.c
 */
bool iface_control(char *name, bool up);
	
/**
 * Implementation of bridge_t.get_name.
 */
static char* get_name(private_bridge_t *this)
{
	return this->name;
}

/**
 * Implementation of bridge_t.create_iface_enumerator.
 */
static enumerator_t* create_iface_enumerator(private_bridge_t *this)
{
	return this->ifaces->create_enumerator(this->ifaces);
}

/**
 * Implementation of bridge_t.disconnect_iface.
 */
static bool disconnect_iface(private_bridge_t *this, iface_t *iface)
{
	enumerator_t *enumerator;
	iface_t *current = NULL;
	bool good = FALSE;

	enumerator = this->ifaces->create_enumerator(this->ifaces);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current == iface)
		{
			if (br_del_interface(this->name, iface->get_hostif(iface)) != 0)
			{
				DBG1("removing iface '%s' from bridge '%s' in kernel failed: %m",
					 iface->get_hostif(iface), this->name);
			}
			else
			{
				iface->set_bridge(iface, NULL);
				this->ifaces->remove_at(this->ifaces, enumerator);
				good = TRUE;
			}
			break;
		}
	}
	if (iface != current)
	{
		DBG1("iface '%s' not found on bridge '%s'", iface->get_hostif(iface),
			 this->name);
	}
	enumerator->destroy(enumerator);
	return good;
}

/**
 * Implementation of bridge_t.connect_iface.
 */
static bool connect_iface(private_bridge_t *this, iface_t *iface)
{
	if (br_add_interface(this->name, iface->get_hostif(iface)) != 0)
	{
		DBG1("adding iface '%s' to bridge '%s' failed: %m",
			 iface->get_hostif(iface), this->name);
		return FALSE;
	}
	iface->set_bridge(iface, &this->public);
	this->ifaces->insert_last(this->ifaces, iface);
	return TRUE;
}

/**
 * instance counter to (de-)initialize libbridge
 */
static int instances = 0;

/**
 * unregister an interface from bridge
 */
static void unregister(iface_t *iface)
{
	iface->set_bridge(iface, NULL);
}

/**
 * Implementation of bridge_t.destroy.
 */
static void destroy(private_bridge_t *this)
{
	this->ifaces->invoke_function(this->ifaces, (linked_list_invoke_t)unregister);
	this->ifaces->destroy(this->ifaces);
	iface_control(this->name, FALSE);
	if (br_del_bridge(this->name) != 0)
	{
		DBG1("deleting bridge '%s' from kernel failed: %m", this->name);
	}
	free(this->name);
	free(this);
	if (--instances == 0)
	{
		br_shutdown();
	}
}

/**
 * create the bridge instance
 */
bridge_t *bridge_create(char *name)
{
	private_bridge_t *this;
	
	if (instances == 0)
	{
		if (br_init() != 0)
		{
			DBG1("libbridge initialization failed: %m");
			return NULL;
		}
	}
	
	this = malloc_thing(private_bridge_t);
	this->public.get_name = (char*(*)(bridge_t*))get_name;
	this->public.create_iface_enumerator = (enumerator_t*(*)(bridge_t*))create_iface_enumerator;
	this->public.disconnect_iface = (bool(*)(bridge_t*, iface_t *iface))disconnect_iface;
	this->public.connect_iface = (bool(*)(bridge_t*, iface_t *iface))connect_iface;
	this->public.destroy = (void*)destroy;

	if (br_add_bridge(name) != 0)
	{
		DBG1("creating bridge '%s' failed: %m", name);
		free(this);
		return NULL;
	}
	if (!iface_control(name, TRUE))
	{
		DBG1("bringing bridge '%s' up failed: %m", name);
	}

	this->name = strdup(name);
	this->ifaces = linked_list_create();

	instances++;
	return &this->public;
}

