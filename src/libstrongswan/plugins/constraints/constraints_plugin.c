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

#include "constraints_plugin.h"

#include <library.h>
#include "constraints_validator.h"

typedef struct private_constraints_plugin_t private_constraints_plugin_t;

/**
 * private data of constraints_plugin
 */
struct private_constraints_plugin_t {

	/**
	 * public functions
	 */
	constraints_plugin_t public;

	/**
	 * Validator implementation instance.
	 */
	constraints_validator_t *validator;
};

METHOD(plugin_t, get_name, char*,
	private_constraints_plugin_t *this)
{
	return "constraints";
}

METHOD(plugin_t, destroy, void,
	private_constraints_plugin_t *this)
{
	lib->credmgr->remove_validator(lib->credmgr, &this->validator->validator);
	this->validator->destroy(this->validator);
	free(this);
}

/*
 * see header file
 */
plugin_t *constraints_plugin_create()
{
	private_constraints_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.validator = constraints_validator_create(),
	);
	lib->credmgr->add_validator(lib->credmgr, &this->validator->validator);

	return &this->public.plugin;
}
