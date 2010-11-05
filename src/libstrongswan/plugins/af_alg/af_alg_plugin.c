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

#include "af_alg_plugin.h"

#include <library.h>

typedef struct private_af_alg_plugin_t private_af_alg_plugin_t;

/**
 * private data of af_alg_plugin
 */
struct private_af_alg_plugin_t {

	/**
	 * public functions
	 */
	af_alg_plugin_t public;
};

METHOD(plugin_t, destroy, void,
	private_af_alg_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *af_alg_plugin_create()
{
	private_af_alg_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
