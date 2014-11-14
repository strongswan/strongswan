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

#include "connmark_plugin.h"

#include <daemon.h>

typedef struct private_connmark_plugin_t private_connmark_plugin_t;

/**
 * private data of connmark plugin
 */
struct private_connmark_plugin_t {

	/**
	 * implements plugin interface
	 */
	connmark_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_connmark_plugin_t *this)
{
	return "connmark";
}

/**
 * Register listener
 */
static bool plugin_cb(private_connmark_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_connmark_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "connmark"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_connmark_plugin_t *this)
{
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *connmark_plugin_create()
{
	private_connmark_plugin_t *this;

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
