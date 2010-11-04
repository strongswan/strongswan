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

#include "tnc_imv_plugin.h"
#include "tnc_imv.h"

#include <daemon.h>

METHOD(plugin_t, destroy, void,
	tnc_imv_plugin_t *this)
{
	imv_t *imv;

	while (charon->imvs->remove_last(charon->imvs, (void**)&imv) == SUCCESS)
	{
		if (imv->terminate(imv->get_id(imv)) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_TNC, "IMV '%s' not terminated successfully",
						   imv->get_name(imv));
		}
		imv->destroy(imv);
	}
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imv_plugin_create()
{
	TNC_IMVID next_id = 1;
	TNC_Version version;
	char *tnc_config, *name, *filename;
	tnc_imv_plugin_t *this;
	imv_t *imv;

	INIT(this,
		.plugin = {
			.destroy = _destroy,
		},
	);

	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imv.tnc_config", "/etc/tnc_config");

	name = "Dummy";
	filename = "/usr/local/lib/libdummyimv.so";
	imv = tnc_imv_create(name, filename, next_id);
	if (imv)
	{
		/* Initialize the module */
	  	if (imv->initialize(next_id, TNC_IFIMV_VERSION_1, TNC_IFIMV_VERSION_1, 
							&version) != TNC_RESULT_SUCCESS)
   		{
			DBG1(DBG_TNC, "could not initialize IMV '%s'\n",
						   imv->get_name(imv));
			imv->destroy(imv);
		}
		else
    	{
			charon->imvs->insert_last(charon->imvs, imv);
			next_id++;
		}
	}
	return &this->plugin;
}

