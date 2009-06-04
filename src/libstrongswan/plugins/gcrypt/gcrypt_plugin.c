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

#include "gcrypt_plugin.h"

#include <library.h>

typedef struct private_gcrypt_plugin_t private_gcrypt_plugin_t;

/**
 * private data of gcrypt_plugin
 */
struct private_gcrypt_plugin_t {

	/**
	 * public functions
	 */
	gcrypt_plugin_t public;
};

/**
 * Implementation of gcrypt_plugin_t.destroy
 */
static void destroy(private_gcrypt_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_gcrypt_plugin_t *this = malloc_thing(private_gcrypt_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	return &this->public.plugin;
}

