/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "soup_plugin.h"
#include "soup_fetcher.h"

#include <glib.h>
#include <glib-object.h>

#include <library.h>

typedef struct private_soup_plugin_t private_soup_plugin_t;

/**
 * private data of soup_plugin
 */
struct private_soup_plugin_t {

	/**
	 * public functions
	 */
	soup_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_soup_plugin_t *this)
{
	return "soup";
}

METHOD(plugin_t, destroy, void,
	private_soup_plugin_t *this)
{
	lib->fetcher->remove_fetcher(lib->fetcher,
								 (fetcher_constructor_t)soup_fetcher_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *soup_plugin_create()
{
	private_soup_plugin_t *this;

	g_type_init();
	if (!g_thread_get_initialized())
	{
		g_thread_init(NULL);
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	lib->fetcher->add_fetcher(lib->fetcher,
					(fetcher_constructor_t)soup_fetcher_create, "http://");
	lib->fetcher->add_fetcher(lib->fetcher,
					(fetcher_constructor_t)soup_fetcher_create, "https://");

	return &this->public.plugin;
}
