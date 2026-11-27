/*
 * Copyright (C) 2026 Manuel Montesdeoca
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

#include "cfg_subnet_plugin.h"
#include "cfg_subnet_handler.h"
#include "cfg_subnet_narrow.h"

#include <daemon.h>

typedef struct private_cfg_subnet_plugin_t private_cfg_subnet_plugin_t;

/**
 * Private data of a cfg_subnet_plugin_t object.
 */
struct private_cfg_subnet_plugin_t {

	/**
	 * Public cfg_subnet_plugin_t interface.
	 */
	cfg_subnet_plugin_t public;

	/**
	 * Attribute handler for subnet attributes
	 */
	cfg_subnet_handler_t *handler;

	/**
	 * Traffic selector narrower, for received subnets
	 */
	cfg_subnet_narrow_t *narrower;

	/**
	 * Whether to request subnet attributes and narrow to them
	 */
	bool enabled;
};

/**
 * Register/unregister handler and listener
 */
static bool plugin_cb(private_cfg_subnet_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (!this->enabled)
	{	/* option disabled: behave as if the plugin were not loaded */
		return TRUE;
	}
	if (reg)
	{
		charon->attributes->add_handler(charon->attributes,
										&this->handler->handler);
		charon->bus->add_listener(charon->bus, &this->narrower->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->narrower->listener);
		charon->attributes->remove_handler(charon->attributes,
										   &this->handler->handler);
	}
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	private_cfg_subnet_plugin_t *this)
{
	return "cfg-subnet";
}

METHOD(plugin_t, get_features, int,
	private_cfg_subnet_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "cfg-subnet"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_cfg_subnet_plugin_t *this)
{
	this->narrower->destroy(this->narrower);
	this->handler->destroy(this->handler);
	free(this);
}

/*
 * see header file
 */
PLUGIN_DEFINE(cfg_subnet)
{
	private_cfg_subnet_plugin_t *this;
	bool enabled;

	enabled = lib->settings->get_bool(lib->settings,
					"charon.plugins.cfg-subnet.request_subnets", FALSE);

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.enabled = enabled,
	);
	this->handler = cfg_subnet_handler_create();
	this->narrower = cfg_subnet_narrow_create(this->handler);

	return &this->public.plugin;
}
