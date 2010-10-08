/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_imc_plugin.h"

#include <libtnctncc.h>

#include <daemon.h>

METHOD(plugin_t, destroy, void,
	tnc_imc_plugin_t *this)
{
	libtnc_tncc_Terminate();
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imc_plugin_create()
{
	char *tnc_config, *pref_lang;
	tnc_imc_plugin_t *this;

	INIT(this,
		.plugin = {
			.destroy = _destroy,
		},
	);

	pref_lang = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.preferred_language", "en");
	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.tnc_config", "/etc/tnc_config");

	if (libtnc_tncc_Initialize(tnc_config) != TNC_RESULT_SUCCESS)
	{
		free(this);
		DBG1(DBG_IKE, "TNC IMC initialization failed");
		return NULL;
	}

	return &this->plugin;
}

