/*
 * Copyright (C) 2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tpm_plugin.h"
#include "tpm_private_key.h"

#include <library.h>

typedef struct private_tpm_plugin_t private_tpm_plugin_t;

/**
 * private data of tpm_plugin
 */
struct private_tpm_plugin_t {

	/**
	 * public functions
	 */
	tpm_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_tpm_plugin_t *this)
{
	return "tpm";
}

METHOD(plugin_t, get_features, int,
	private_tpm_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(PRIVKEY, tpm_private_key_connect, FALSE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ANY),
	};
	*features = f;

	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_tpm_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *tpm_plugin_create()
{
	private_tpm_plugin_t *this;

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
