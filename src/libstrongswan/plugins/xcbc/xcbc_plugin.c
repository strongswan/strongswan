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

#include "xcbc_plugin.h"

#include <library.h>
#include "xcbc_signer.h"
#include "xcbc_prf.h"

typedef struct private_xcbc_plugin_t private_xcbc_plugin_t;

/**
 * private data of xcbc_plugin
 */
struct private_xcbc_plugin_t {

	/**
	 * public functions
	 */
	xcbc_plugin_t public;
};

/**
 * Implementation of xcbc_plugin_t.xcbctroy
 */
static void destroy(private_xcbc_plugin_t *this)
{
	lib->crypto->remove_prf(lib->crypto,
							(prf_constructor_t)xcbc_prf_create);
	lib->crypto->remove_signer(lib->crypto,
							   (signer_constructor_t)xcbc_signer_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_xcbc_plugin_t *this = malloc_thing(private_xcbc_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_prf(lib->crypto, PRF_AES128_XCBC, 
						 (prf_constructor_t)xcbc_prf_create);
	lib->crypto->add_signer(lib->crypto, AUTH_AES_XCBC_96, 
							(signer_constructor_t)xcbc_signer_create);

	return &this->public.plugin;
}

