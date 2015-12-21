/*
 * Copyright (C) 2015-2016 Andreas Steffen
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


#include "demo_plugin.h"
#include "demo_listener.h"

#include <daemon.h>

typedef struct private_demo_plugin_t private_demo_plugin_t;

/**
 * Private data of a demo_plugin_t object.
 */
struct private_demo_plugin_t {

	/**
	 * Public radius_plugin_t interface.
	 */
	demo_plugin_t public;

	/**
	 * Message listener inserting and processing DEMO notify payload
	 */
	demo_listener_t *demo;
};

METHOD(plugin_t, get_name, char*,
	private_demo_plugin_t *this)
{
	return "demo";
}

/**
 * Register listener
 */
static bool plugin_cb(private_demo_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->demo = demo_listener_create();
		if (this->demo)
		{
			charon->bus->add_listener(charon->bus, &this->demo->listener);
		}
	}
	else
	{
		if (this->demo)
		{
			charon->bus->remove_listener(charon->bus, &this->demo->listener);
			this->demo->destroy(this->demo);
		}
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_demo_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "demo"),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_demo_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *demo_plugin_create()
{
	private_demo_plugin_t *this;

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
