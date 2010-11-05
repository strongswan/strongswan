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
#include "tnc_imv_manager.h"
#include "tnc_imv.h"

#include <daemon.h>

METHOD(plugin_t, destroy, void,
	tnc_imv_plugin_t *this)
{
	charon->imvs->destroy(charon->imvs);
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imv_plugin_create()
{
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

	/* Create IMV manager */
	charon->imvs = tnc_imv_manager_create();

	/* Create and register IMVs */
	name = "Dummy";
	filename = "/usr/local/lib/libdummyimv.so";
	imv = tnc_imv_create(name, filename);
	if (imv)
	{
		if (!charon->imvs->add(charon->imvs, imv))
		{
			imv->destroy(imv);
		}
	}
	return &this->plugin;
}

