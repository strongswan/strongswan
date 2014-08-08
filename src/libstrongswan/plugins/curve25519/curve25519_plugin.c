/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "curve25519_plugin.h"
#include "curve25519_dh.h"

#include <library.h>

typedef struct private_curve25519_plugin_t private_curve25519_plugin_t;

/**
 * private data of curve25519_plugin
 */
struct private_curve25519_plugin_t {

	/**
	 * public functions
	 */
	curve25519_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_curve25519_plugin_t *this)
{
	return "curve25519";
}

METHOD(plugin_t, get_features, int,
	private_curve25519_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(DH, curve25519_dh_create),
			PLUGIN_PROVIDE(DH, CURVE_25519),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_curve25519_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *curve25519_plugin_create()
{
	private_curve25519_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
