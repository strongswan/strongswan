/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2022 Noel Kuntze
 *
 * Copyright (C) secunet Security Networks AG
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

#include "updownv2_plugin.h"
#include "updownv2_listener.h"
#include "updownv2_handler.h"

#include <daemon.h>

typedef struct private_updownv2_plugin_t private_updownv2_plugin_t;

/**
 * private data of updown plugin
 */
struct private_updownv2_plugin_t {

	/**
	 * implements plugin interface
	 */
	updownv2_plugin_t public;

	/**
	 * Listener interface, listens to CHILD_SA state changes
	 */
	updownv2_listener_t *listener;

	/**
	 * Attribute handler, to pass DNS servers to updown
	 */
	updownv2_handler_t *handler;
};

METHOD(plugin_t, get_name, char*,
	private_updownv2_plugin_t *this)
{
	return "updownv2";
}

/**
 * Register listener
 */
static bool plugin_cb(private_updownv2_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		if (lib->settings->get_bool(lib->settings,
							"%s.plugins.updownv2.dns_handler", FALSE, lib->ns))
		{
			this->handler = updownv2_handler_create();
			charon->attributes->add_handler(charon->attributes,
											&this->handler->handler);
		}
		this->listener = updownv2_listener_create(this->handler);
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
		this->listener->destroy(this->listener);
		if (this->handler)
		{
			this->handler->destroy(this->handler);
			charon->attributes->remove_handler(charon->attributes,
											   &this->handler->handler);
		}
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_updownv2_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "updownv2"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_updownv2_plugin_t *this)
{
	return this->listener->reload(this->listener);
}

METHOD(plugin_t, destroy, void,
	private_updownv2_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *updownv2_plugin_create()
{
	private_updownv2_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = _reload,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
