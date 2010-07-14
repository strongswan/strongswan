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

#include "pkcs11_plugin.h"

#include <library.h>

#include "pkcs11_manager.h"

typedef struct private_pkcs11_plugin_t private_pkcs11_plugin_t;

/**
 * private data of pkcs11_plugin
 */
struct private_pkcs11_plugin_t {

	/**
	 * public functions
	 */
	pkcs11_plugin_t public;

	/**
	 * PKCS#11 library/slot manager
	 */
	pkcs11_manager_t *manager;
};

METHOD(plugin_t, destroy, void,
	private_pkcs11_plugin_t *this)
{
	this->manager->destroy(this->manager);
	free(this);
}

/*
 * see header file
 */
plugin_t *pkcs11_plugin_create()
{
	private_pkcs11_plugin_t *this;

	INIT(this,
		.public.plugin.destroy = _destroy,
		.manager = pkcs11_manager_create(),
	);

	return &this->public.plugin;
}
