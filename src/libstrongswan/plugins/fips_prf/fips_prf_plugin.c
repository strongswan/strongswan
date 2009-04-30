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

#include "fips_prf_plugin.h"

#include <library.h>
#include "fips_prf.h"

typedef struct private_fips_prf_plugin_t private_fips_prf_plugin_t;

/**
 * private data of fips_prf_plugin
 */
struct private_fips_prf_plugin_t {

	/**
	 * public functions
	 */
	fips_prf_plugin_t public;
};

/**
 * Implementation of fips_prf_plugin_t.destroy
 */
static void destroy(private_fips_prf_plugin_t *this)
{
	lib->crypto->remove_prf(lib->crypto,
							(prf_constructor_t)fips_prf_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_fips_prf_plugin_t *this = malloc_thing(private_fips_prf_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_prf(lib->crypto, PRF_FIPS_SHA1_160,
						 (prf_constructor_t)fips_prf_create);
	
	return &this->public.plugin;
}
