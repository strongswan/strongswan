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

METHOD(plugin_t, get_name, char*,
	private_fips_prf_plugin_t *this)
{
	return "fips-prf";
}

METHOD(plugin_t, destroy, void,
	private_fips_prf_plugin_t *this)
{
	lib->crypto->remove_prf(lib->crypto,
							(prf_constructor_t)fips_prf_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *fips_prf_plugin_create()
{
	private_fips_prf_plugin_t *this;
	prf_t *prf;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	prf = lib->crypto->create_prf(lib->crypto, PRF_KEYED_SHA1);
	if (prf)
	{
		prf->destroy(prf);
		lib->crypto->add_prf(lib->crypto, PRF_FIPS_SHA1_160, get_name(this),
							 (prf_constructor_t)fips_prf_create);
	}

	return &this->public.plugin;
}
