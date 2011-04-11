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

#include "addrblock_plugin.h"

#include <daemon.h>

#include "addrblock_validator.h"
#include "addrblock_narrow.h"

typedef struct private_addrblock_plugin_t private_addrblock_plugin_t;

/**
 * private data of addrblock_plugin
 */
struct private_addrblock_plugin_t {

	/**
	 * public functions
	 */
	addrblock_plugin_t public;

	/**
	 * Validator implementation instance.
	 */
	addrblock_validator_t *validator;

	/**
	 * Listener to check TS list
	 */
	addrblock_narrow_t *narrower;
};

METHOD(plugin_t, get_name, char*,
	private_addrblock_plugin_t *this)
{
	return "addrblock";
}

METHOD(plugin_t, destroy, void,
	private_addrblock_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->narrower->listener);
	lib->credmgr->remove_validator(lib->credmgr, &this->validator->validator);
	this->narrower->destroy(this->narrower);
	this->validator->destroy(this->validator);
	free(this);
}

/*
 * see header file
 */
plugin_t *addrblock_plugin_create()
{
	private_addrblock_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.validator = addrblock_validator_create(),
		.narrower = addrblock_narrow_create(),
	);
	lib->credmgr->add_validator(lib->credmgr, &this->validator->validator);
	charon->bus->add_listener(charon->bus, &this->narrower->listener);

	return &this->public.plugin;
}
