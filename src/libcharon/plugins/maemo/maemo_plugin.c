/*
 * Copyright (C) 2010 Tobias Brunner
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

#include "maemo_plugin.h"

#include <daemon.h>

typedef struct private_maemo_plugin_t private_maemo_plugin_t;

/**
 * private data of maemo plugin
 */
struct private_maemo_plugin_t {

	/**
	 * implements plugin interface
	 */
	maemo_plugin_t public;

};

METHOD(plugin_t, destroy, void,
	   private_maemo_plugin_t *this)
{
	free(this);
}

/*
 * See header
 */
plugin_t *maemo_plugin_create()
{
	private_maemo_plugin_t *this;

	INIT(this,
		.public.plugin = {
			.destroy = _destroy,
		},
	);

	return &this->public.plugin;
}

