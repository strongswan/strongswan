/*
 * Copyright (C) 2008 Martin Willi
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

#include "curl_plugin.h"

#include <library.h>
#include <utils/debug.h>
#include "curl_fetcher.h"

#include <curl/curl.h>

typedef struct private_curl_plugin_t private_curl_plugin_t;

/**
 * private data of curl_plugin
 */
struct private_curl_plugin_t {

	/**
	 * public functions
	 */
	curl_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_curl_plugin_t *this)
{
	return "curl";
}

METHOD(plugin_t, get_features, int,
	private_curl_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(FETCHER, curl_fetcher_create),
			PLUGIN_PROVIDE(FETCHER, "file://"),
			PLUGIN_PROVIDE(FETCHER, "http://"),
			PLUGIN_PROVIDE(FETCHER, "https://"),
			PLUGIN_PROVIDE(FETCHER, "ftp://"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_curl_plugin_t *this)
{
	curl_global_cleanup();
	free(this);
}

/*
 * see header file
 */
plugin_t *curl_plugin_create()
{
	CURLcode res;
	private_curl_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	res = curl_global_init(CURL_GLOBAL_NOTHING);
	if (res != CURLE_OK)
	{
		DBG1(DBG_LIB, "global libcurl initializing failed: %s",
			 curl_easy_strerror(res));
		destroy(this);
		return NULL;
	}
	return &this->public.plugin;
}

