/*
 * Copyright (C) 2020 Stafan Gula
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

#include "eap_anyconnect_plugin.h"
#include "eap_anyconnect.h"

#include <daemon.h>

METHOD(plugin_t, get_name, char*,
	eap_anyconnect_plugin_t *this)
{
	return "eap-anyconnect";
}

bool eap_anyconnect_register(plugin_t *plugin, plugin_feature_t *feature,
						 bool reg, void *data)
{
	bool ret = eap_method_register(plugin, feature, reg, data);
	if (!ret)
	{
		DBG1(DBG_IKE, "eap_anyconnect registration callback failed");
		return ret;
	}

	return TRUE;
}

METHOD(plugin_t, get_features, int,
	eap_anyconnect_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(eap_anyconnect_register, eap_anyconnect_create_server),
			PLUGIN_PROVIDE(EAP_SERVER_VENDOR, EAP_ANYCONNECT, EAP_VENDOR_CISCO),
		PLUGIN_CALLBACK(eap_anyconnect_register, eap_anyconnect_create_peer),
			PLUGIN_PROVIDE(EAP_PEER_VENDOR, EAP_ANYCONNECT, EAP_VENDOR_CISCO),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	eap_anyconnect_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_anyconnect_plugin_create()
{
	eap_anyconnect_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);

	return &this->plugin;
}

