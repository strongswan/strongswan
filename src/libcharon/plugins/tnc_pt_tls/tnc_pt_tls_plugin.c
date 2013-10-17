/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "tnc_pt_tls_plugin.h"
#include "tnc_pt_tls_connection.h"

#include "pt_tls_manager.h"

#include <daemon.h>

typedef struct private_tnc_pt_tls_plugin_t private_tnc_pt_tls_plugin_t;

/**
 * Private data of a tnc_pt_tls_plugin_t object.
 */
struct private_tnc_pt_tls_plugin_t {

	/**
	 * Public interface.
	 */
	pt_tls_plugin_t public;

	/**
	 * PT-TLS backend manager
	 */
	pt_tls_manager_t *mgr;
};


METHOD(plugin_t, get_name, char*,
	private_tnc_pt_tls_plugin_t *this)
{
	return "tnc-pt-tls";
}

/**
 * Register PT-TLS manager
 */
static bool plugin_cb(private_tnc_pt_tls_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		lib->set(lib, "pt-tls-manager", this->mgr);
	}
	else
	{
		lib->set(lib, "pt-tls-manager", NULL);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_tnc_pt_tls_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "pt-tls-manager"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_tnc_pt_tls_plugin_t *this)
{
	this->mgr->destroy(this->mgr);
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_pt_tls_plugin_create()
{
	private_tnc_pt_tls_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.mgr = pt_tls_manager_create(tnc_pt_tls_connection_create),
	);

	return &this->public.plugin;
}

