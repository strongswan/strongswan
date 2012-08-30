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

#include "eap_ms_soh_plugin.h"

#include "eap_ms_soh.h"

#include <daemon.h>

METHOD(plugin_t, get_name, char*,
	eap_ms_soh_plugin_t *this)
{
	return "eap-ms-soh";
}

/**
 * Callback function registering EAP-SOH
 */
static bool register_eap_ms_soh(plugin_t *plugin, plugin_feature_t *feature,
							 bool reg, void *data)
{
	if (reg)
	{
		charon->eap->add_method(charon->eap, EAP_MS_SOH, PEN_MICROSOFT,
					data == eap_ms_soh_create_server ? EAP_SERVER : EAP_PEER,
					(eap_constructor_t)data);
	}
	else
	{
		charon->eap->remove_method(charon->eap, (eap_constructor_t)data);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	eap_ms_soh_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(register_eap_ms_soh, eap_ms_soh_create_server),
			PLUGIN_PROVIDE(CUSTOM, "EAP-MS-SOH server"),
		PLUGIN_CALLBACK(register_eap_ms_soh, eap_ms_soh_create_peer),
			PLUGIN_PROVIDE(CUSTOM, "EAP-MS-SOH client"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	eap_ms_soh_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_ms_soh_plugin_create()
{
	eap_ms_soh_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);

	return &this->plugin;
}
