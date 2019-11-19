/*
 * Copyright (C) 2019 Tobias Brunner
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

#include "link_local_ts_plugin.h"

#include <daemon.h>
#include <plugins/plugin_feature.h>

#include "link_local_ts_narrow.h"

typedef struct private_link_local_ts_plugin_t private_link_local_ts_plugin_t;

/**
 * Private plugin data
 */
struct private_link_local_ts_plugin_t {

	/**
	 * Public interface.
	 */
	link_local_ts_plugin_t public;

	/**
	 * Listener to narrow traffic selectors.
	 */
	link_local_ts_narrow_t *narrower;
};

METHOD(plugin_t, get_name, char*,
	private_link_local_ts_plugin_t *this)
{
	return "link-local-ts";
}

/**
 * Register listener
 */
static bool plugin_cb(private_link_local_ts_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->bus->add_listener(charon->bus, &this->narrower->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->narrower->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_link_local_ts_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "link-local-ts"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_link_local_ts_plugin_t *this)
{
	this->narrower->destroy(this->narrower);
	free(this);
}

/*
 * Described in header
 */
plugin_t *link_local_ts_plugin_create()
{
	private_link_local_ts_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.narrower = link_local_ts_narrow_create(),
	);

	return &this->public.plugin;
}
