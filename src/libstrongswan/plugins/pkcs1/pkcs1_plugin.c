/*
 * Copyright (C) 2009 Martin Willi
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

#include "pkcs1_plugin.h"

#include <library.h>
#include "pkcs1_builder.h"

typedef struct private_pkcs1_plugin_t private_pkcs1_plugin_t;

/**
 * private data of pkcs1_plugin
 */
struct private_pkcs1_plugin_t {

	/**
	 * public functions
	 */
	pkcs1_plugin_t public;
};

/**
 * Implementation of pkcs1_plugin_t.pkcs1troy
 */
static void destroy(private_pkcs1_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							(builder_constructor_t)pkcs1_public_key_builder);
	lib->creds->remove_builder(lib->creds,
							(builder_constructor_t)pkcs1_private_key_builder);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_pkcs1_plugin_t *this = malloc_thing(private_pkcs1_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
							(builder_constructor_t)pkcs1_public_key_builder);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
							(builder_constructor_t)pkcs1_public_key_builder);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							(builder_constructor_t)pkcs1_private_key_builder);
	
	return &this->public.plugin;
}

