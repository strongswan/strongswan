/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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

#include "twofish_plugin.h"

#include <library.h>
#include "twofish_crypter.h"

typedef struct private_twofish_plugin_t private_twofish_plugin_t;

/**
 * private data of twofish_plugin
 */
struct private_twofish_plugin_t {

	/**
	 * public functions
	 */
	twofish_plugin_t public;
};

/**
 * Implementation of twofish_plugin_t.destroy
 */
static void destroy(private_twofish_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
								(crypter_constructor_t)twofish_crypter_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_twofish_plugin_t *this = malloc_thing(private_twofish_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_crypter(lib->crypto, ENCR_TWOFISH,
							 (crypter_constructor_t)twofish_crypter_create);
	
	return &this->public.plugin;
}

