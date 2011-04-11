/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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

#include "blowfish_plugin.h"

#include <library.h>
#include "blowfish_crypter.h"

typedef struct private_blowfish_plugin_t private_blowfish_plugin_t;

/**
 * private data of blowfish_plugin
 */
struct private_blowfish_plugin_t {

	/**
	 * public functions
	 */
	blowfish_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_blowfish_plugin_t *this)
{
	return "blowfish";
}

METHOD(plugin_t, destroy, void,
	private_blowfish_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
								(crypter_constructor_t)blowfish_crypter_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *blowfish_plugin_create()
{
	private_blowfish_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	lib->crypto->add_crypter(lib->crypto, ENCR_BLOWFISH, get_name(this),
							 (crypter_constructor_t)blowfish_crypter_create);

	return &this->public.plugin;
}

