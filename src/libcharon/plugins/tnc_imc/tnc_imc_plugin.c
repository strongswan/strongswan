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
#include "tnc_imc.h"

#include <daemon.h>

METHOD(plugin_t, destroy, void,
	tnc_imc_plugin_t *this)
{
	imc_t *imc;

	while (charon->imcs->remove_last(charon->imcs, (void**)&imc) == SUCCESS)
	{
		if (imc->terminate(imc->get_id(imc)) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_TNC, "IMC '%s' not terminated successfully",
						   imc->get_name(imc));
		}
		imc->destroy(imc);
	}
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imc_plugin_create()
{
	TNC_IMCID next_id = 1;
	TNC_Version version;
	char *tnc_config, *pref_lang, *name, *filename;
	tnc_imc_plugin_t *this;
	imc_t *imc;
	

	INIT(this,
		.plugin = {
			.destroy = _destroy,
		},
	);

	pref_lang = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.preferred_language", "en");
	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.tnc_config", "/etc/tnc_config");

	name = "Dummy";
	filename = "/usr/local/lib/libdummyimc.so";
	imc = tnc_imc_create(name, filename, next_id);
	if (imc)
	{
		/* Initialize the module */
	  	if (imc->initialize(next_id, TNC_IFIMC_VERSION_1, TNC_IFIMC_VERSION_1, 
							&version) != TNC_RESULT_SUCCESS)
   		{
			DBG1(DBG_TNC, "could not initialize IMC '%s'\n",
						   imc->get_name(imc));
			imc->destroy(imc);
		}
		else
    	{
			charon->imcs->insert_last(charon->imcs, imc);
			next_id++;
		}
	}
	return &this->plugin;
}

