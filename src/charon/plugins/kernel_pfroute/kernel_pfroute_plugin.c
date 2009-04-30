/*
 * Copyright (C) 2009 Tobias Brunner
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
 *
 * $Id$
 */


#include "kernel_pfroute_plugin.h"

#include "kernel_pfroute_net.h"

#include <daemon.h>

typedef struct private_kernel_pfroute_plugin_t private_kernel_pfroute_plugin_t;

/**
 * private data of kernel PF_ROUTE plugin
 */
struct private_kernel_pfroute_plugin_t {
	/**
	 * implements plugin interface
	 */
	kernel_pfroute_plugin_t public;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_kernel_pfroute_plugin_t *this)
{
	charon->kernel_interface->remove_net_interface(charon->kernel_interface,
						(kernel_net_constructor_t)kernel_pfroute_net_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_kernel_pfroute_plugin_t *this = malloc_thing(private_kernel_pfroute_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	charon->kernel_interface->add_net_interface(charon->kernel_interface,
						(kernel_net_constructor_t)kernel_pfroute_net_create);
	
	return &this->public.plugin;
}
