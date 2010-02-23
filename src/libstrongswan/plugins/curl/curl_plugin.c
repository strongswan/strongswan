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
#include <debug.h>
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

/**
 * Implementation of curl_plugin_t.curltroy
 */
static void destroy(private_curl_plugin_t *this)
{
	lib->fetcher->remove_fetcher(lib->fetcher,
								 (fetcher_constructor_t)curl_fetcher_create);
	curl_global_cleanup();
	free(this);
}

/*
 * see header file
 */
plugin_t *curl_plugin_create()
{
	CURLcode res;
	private_curl_plugin_t *this = malloc_thing(private_curl_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	res = curl_global_init(CURL_GLOBAL_NOTHING);
	if (res == CURLE_OK)
	{
		lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)curl_fetcher_create, "file://");
		lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)curl_fetcher_create, "http://");
		lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)curl_fetcher_create, "https://");
		lib->fetcher->add_fetcher(lib->fetcher,
						(fetcher_constructor_t)curl_fetcher_create, "ftp://");
	}
	else
	{
		DBG1("global libcurl initializing failed: %s, curl disabled",
			 curl_easy_strerror(res));
	}
	return &this->public.plugin;
}

