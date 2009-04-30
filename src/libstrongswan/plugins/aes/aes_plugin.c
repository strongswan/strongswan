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

#include "aes_plugin.h"

#include <library.h>
#include "aes_crypter.h"

typedef struct private_aes_plugin_t private_aes_plugin_t;

/**
 * private data of aes_plugin
 */
struct private_aes_plugin_t {

	/**
	 * public functions
	 */
	aes_plugin_t public;
};

/**
 * Implementation of aes_plugin_t.destroy
 */
static void destroy(private_aes_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
								(crypter_constructor_t)aes_crypter_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_aes_plugin_t *this = malloc_thing(private_aes_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC,
							 (crypter_constructor_t)aes_crypter_create);
	
	return &this->public.plugin;
}

