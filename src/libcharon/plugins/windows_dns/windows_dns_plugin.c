/*
 * Copyright (C) 2018 Sophos Group plc
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

#include "windows_dns_plugin.h"
#include "windows_dns_handler.h"

#include <daemon.h>

typedef struct private_windows_dns_plugin_t private_windows_dns_plugin_t;

/**
 * Private data of an windows_dns_plugin_t object.
 */
struct private_windows_dns_plugin_t {

	/**
	 * Public interface
	 */
	windows_dns_plugin_t public;

	/**
	 * Windows specific DNS handler
	 */
	windows_dns_handler_t *handler;
};

METHOD(plugin_t, get_name, char*,
	private_windows_dns_plugin_t *this)
{
	return "windows-dns";
}

/**
 * Register handler
 */
static bool plugin_cb(private_windows_dns_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->attributes->add_handler(charon->attributes,
										&this->handler->handler);
	}
	else
	{
		charon->attributes->remove_handler(charon->attributes,
										   &this->handler->handler);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_windows_dns_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "windows-dns"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_windows_dns_plugin_t *this)
{
	this->handler->destroy(this->handler);
	free(this);
}

/**
 * See header
 */
plugin_t *windows_dns_plugin_create()
{
	private_windows_dns_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.handler = windows_dns_handler_create(),
	);

	return &this->public.plugin;
}
