/*
 * Copyright (C) 2008 Martin Willi
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

#include "ldap_plugin.h"

#include <library.h>
#include "ldap_fetcher.h"

typedef struct private_ldap_plugin_t private_ldap_plugin_t;

/**
 * private data of ldap_plugin
 */
struct private_ldap_plugin_t {

	/**
	 * public functions
	 */
	ldap_plugin_t public;
};

/**
 * Implementation of ldap_plugin_t.destroy
 */
static void destroy(private_ldap_plugin_t *this)
{
	lib->fetcher->remove_fetcher(lib->fetcher, 
								 (fetcher_constructor_t)ldap_fetcher_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_ldap_plugin_t *this = malloc_thing(private_ldap_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)ldap_fetcher_create, "ldap://");
	lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)ldap_fetcher_create, "ldaps://");
	
	return &this->public.plugin;
}

