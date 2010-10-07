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
	int imc_count;
	tnc_imc_plugin_t *this;

	INIT(this,
		.plugin = {
			.destroy = _destroy,
		},
	);

	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.tnc_config", "/etc/tnc_config");
	pref_lang = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.preferred_language", "en");
	imc_count = libtnc_imc_load_config(tnc_config);
	if (imc_count < 0)
	{
		free(this);
		DBG1(DBG_IKE, "TNC IMC initialization failed");
		return NULL;
	}
	else
	{
		DBG1(DBG_IKE, "loaded %d TNC IMC%s", imc_count, (imc_count > 1)? "s":"");
		libtnc_tncc_PreferredLanguage(pref_lang);
	}

	return &this->plugin;
}

