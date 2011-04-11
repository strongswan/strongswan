/*
 * Copyright (C) 2009 Martin Willi
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

#include "dnskey_plugin.h"

#include <library.h>
#include "dnskey_builder.h"

typedef struct private_dnskey_plugin_t private_dnskey_plugin_t;

/**
 * private data of dnskey_plugin
 */
struct private_dnskey_plugin_t {

	/**
	 * public functions
	 */
	dnskey_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_dnskey_plugin_t *this)
{
	return "dnskey";
}

METHOD(plugin_t, destroy, void,
	private_dnskey_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							(builder_function_t)dnskey_public_key_load);
	free(this);
}

/*
 * see header file
 */
plugin_t *dnskey_plugin_create()
{
	private_dnskey_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY, FALSE,
							(builder_function_t)dnskey_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA, FALSE,
							(builder_function_t)dnskey_public_key_load);

	return &this->public.plugin;
}

