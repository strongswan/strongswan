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

#include "keychain_plugin.h"
#include "keychain_creds.h"

#include <library.h>

typedef struct private_keychain_plugin_t private_keychain_plugin_t;

/**
 * private data of keychain_plugin
 */
struct private_keychain_plugin_t {

	/**
	 * public functions
	 */
	keychain_plugin_t public;

	/**
	 * System level Keychain Services credential set
	 */
	keychain_creds_t *creds;
};

METHOD(plugin_t, get_name, char*,
	private_keychain_plugin_t *this)
{
	return "keychain";
}

METHOD(plugin_t, destroy, void,
	private_keychain_plugin_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

/*
 * see header file
 */
plugin_t *keychain_plugin_create()
{
	private_keychain_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.destroy = _destroy,
			},
		},
		.creds = keychain_creds_create(),
	);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	return &this->public.plugin;
}
