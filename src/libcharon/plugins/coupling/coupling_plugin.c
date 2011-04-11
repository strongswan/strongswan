/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "coupling_plugin.h"

#include "coupling_validator.h"

#include <daemon.h>

typedef struct private_coupling_plugin_t private_coupling_plugin_t;

/**
 * private data of coupling plugin
 */
struct private_coupling_plugin_t {

	/**
	 * implements plugin interface
	 */
	coupling_plugin_t public;

	/**
	 * validator controlling couplings
	 */
	coupling_validator_t *validator;
};

METHOD(plugin_t, get_name, char*,
	private_coupling_plugin_t *this)
{
	return "coupling";
}

METHOD(plugin_t, destroy, void,
	private_coupling_plugin_t *this)
{
	lib->credmgr->remove_validator(lib->credmgr, &this->validator->validator);
	this->validator->destroy(this->validator);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *coupling_plugin_create()
{
	private_coupling_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.validator = coupling_validator_create(),
	);

	if (!this->validator)
	{
		free(this);
		return NULL;
	}

	lib->credmgr->add_validator(lib->credmgr, &this->validator->validator);

	return &this->public.plugin;
}
