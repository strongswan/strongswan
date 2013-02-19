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

#include "systime_fix_plugin.h"

#include <daemon.h>

typedef struct private_systime_fix_plugin_t private_systime_fix_plugin_t;

/**
 * Private data of systime_fix plugin
 */
struct private_systime_fix_plugin_t {

	/**
	 * Implements plugin interface
	 */
	systime_fix_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_systime_fix_plugin_t *this)
{
	return "systime-fix";
}

METHOD(plugin_t, destroy, void,
	private_systime_fix_plugin_t *this)
{
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *systime_fix_plugin_create()
{
	private_systime_fix_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
