/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

#include "kernel_libipsec_plugin.h"
#include "kernel_libipsec_ipsec.h"

#include <ipsec.h>
#include <utils/debug.h>

typedef struct private_kernel_libipsec_plugin_t private_kernel_libipsec_plugin_t;

/**
 * private data of "kernel" libipsec plugin
 */
struct private_kernel_libipsec_plugin_t {

	/**
	 * implements plugin interface
	 */
	kernel_libipsec_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_kernel_libipsec_plugin_t *this)
{
	return "kernel-libipsec";
}

METHOD(plugin_t, get_features, int,
	private_kernel_libipsec_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_libipsec_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_kernel_libipsec_plugin_t *this)
{
	libipsec_deinit();
	free(this);
}

/*
 * see header file
 */
plugin_t *kernel_libipsec_plugin_create()
{
	private_kernel_libipsec_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	if (!libipsec_init())
	{
		DBG1(DBG_LIB, "initialization of libipsec failed");
		destroy(this);
		return NULL;
	}

	return &this->public.plugin;
}
