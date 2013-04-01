/*
 * Copyright (C) 2012 Reto Guadagnini
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

#include "ipseckey_plugin.h"

#include <daemon.h>
#include "ipseckey_cred.h"

typedef struct private_ipseckey_plugin_t private_ipseckey_plugin_t;


/**
 * private data of the ipseckey plugin
 */
struct private_ipseckey_plugin_t {

	/**
	 * implements plugin interface
	 */
	ipseckey_plugin_t public;

	/**
	 * DNS resolver instance
	 */
	resolver_t *res;

	/**
	 * credential set
	 */
	ipseckey_cred_t *cred;

	/**
	 * IPSECKEY based authentication enabled
	 */
	bool enabled;
};

METHOD(plugin_t, get_name, char*,
	private_ipseckey_plugin_t *this)
{
	return "ipseckey";
}

METHOD(plugin_t, destroy, void,
	private_ipseckey_plugin_t *this)
{
	if (this->enabled)
	{
		lib->credmgr->remove_set(lib->credmgr, &this->cred->set);
	}
	DESTROY_IF(this->res);
	DESTROY_IF(this->cred);
	free(this);
}

/*
 * see header file
 */
plugin_t *ipseckey_plugin_create()
{
	private_ipseckey_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.res = lib->resolver->create(lib->resolver),
		.enabled = lib->settings->get_bool(lib->settings,
							"%s.plugins.ipseckey.enable", FALSE, charon->name),
	);

	if (!this->res)
	{
		DBG1(DBG_CFG, "failed to create a DNS resolver instance");
		destroy(this);
		return NULL;
	}

	if (this->enabled)
	{
		this->cred = ipseckey_cred_create(this->res);
		lib->credmgr->add_set(lib->credmgr, &this->cred->set);
	}

	return &this->public.plugin;
}

