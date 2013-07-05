/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "tls_stream_plugin.h"
#include "tls_stream.h"
#include "tls_stream_service.h"

#include <library.h>

typedef struct private_tls_stream_plugin_t private_tls_stream_plugin_t;

/**
 * Private data of tls_stream_plugin
 */
struct private_tls_stream_plugin_t {

	/**
	 * public functions
	 */
	tls_stream_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_tls_stream_plugin_t *this)
{
	return "tls-stream";
}

METHOD(plugin_t, get_features, int,
	private_tls_stream_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(STREAM, tls_stream_create),
			PLUGIN_PROVIDE(STREAM, "tcp+tls://"),
		PLUGIN_REGISTER(STREAM_SERVICE, tls_stream_service_create),
			PLUGIN_PROVIDE(STREAM_SERVICE, "tcp+tls://"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_tls_stream_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *tls_stream_plugin_create()
{
	private_tls_stream_plugin_t *this;

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
