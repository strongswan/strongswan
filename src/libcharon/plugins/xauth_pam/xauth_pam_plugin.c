/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "xauth_pam_plugin.h"
#include "xauth_pam.h"

#include <daemon.h>

#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif

METHOD(plugin_t, get_name, char*,
	xauth_pam_plugin_t *this)
{
	return "xauth-pam";
}

METHOD(plugin_t, get_features, int,
	xauth_pam_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(xauth_method_register, xauth_pam_create_server),
			PLUGIN_PROVIDE(XAUTH_SERVER, "pam"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	xauth_pam_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *xauth_pam_plugin_create()
{
	xauth_pam_plugin_t *this;

	/* required for PAM authentication */
	if (!lib->caps->keep(lib->caps, CAP_AUDIT_WRITE))
	{
		DBG1(DBG_DMN, "xauth-pam plugin requires CAP_AUDIT_WRITE capability");
		return NULL;
	}

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);

	return &this->plugin;
}
