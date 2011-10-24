/*
 * Copyright (C) 2011 Andreas Steffen
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

#include "tnc.h"

typedef struct private_tnc_t private_tnc_t;

typedef tnccs_manager_t *(*tnc_create_tnccs_manager_t)(void);
typedef imc_manager_t *(*tnc_create_imc_manager_t)(void);
typedef imv_manager_t *(*tnc_create_imv_manager_t)(void);

/**
 * Private additions to tnc_t.
 */
struct private_tnc_t {

	/**
	 * Public members of tnc_t.
	 */
	tnc_t public;
};

/**
 * Single instance of tnc_t.
 */
tnc_t *tnc;

/**
 * Described in header.
 */
void libtnccs_init(void)
{
	private_tnc_t *this;

	INIT(this,
		.public = {
		},
	);	

	tnc = &this->public;
}

/**
 * Described in header.
 */
void libtnccs_deinit(void)
{
	private_tnc_t *this = (private_tnc_t*)tnc;

	free(this);
	tnc = NULL;
}

/**
 * Described in header.
 */
bool tnc_manager_register(plugin_t *plugin, plugin_feature_t *feature,
						  bool reg, void *data)
{
	char *tnc_config;

	tnc_config = lib->settings->get_str(lib->settings,
						"libtnccs.tnc_config", "/etc/tnc_config");

	if (feature->type == FEATURE_CUSTOM)
	{
		if (streq(feature->arg.custom, "tnccs-manager"))
		{
			if (reg)
			{
				tnc->tnccs = ((tnc_create_tnccs_manager_t)data)();
			}
			else
			{
				tnc->tnccs->destroy(tnc->tnccs);
				tnc->tnccs = NULL;
			}
		}
		else if (streq(feature->arg.custom, "imc-manager"))
		{
			if (reg)
			{
				tnc->imcs = ((tnc_create_imc_manager_t)data)();


				if (!tnc->imcs->load_all(tnc->imcs, tnc_config))
				{
					tnc->imcs->destroy(tnc->imcs);
					tnc->imcs = NULL;
					return FALSE;
				}
			}
			else
			{
				tnc->imcs->destroy(tnc->imcs);
				tnc->imcs = NULL;
			}
		}
		else if (streq(feature->arg.custom, "imv-manager"))
		{
			if (reg)
			{
				tnc->imvs = ((tnc_create_imv_manager_t)data)();

				if (!tnc->imvs->load_all(tnc->imvs, tnc_config))
				{
					tnc->imvs->destroy(tnc->imvs);
					tnc->imvs = NULL;
					return FALSE;
				}
			}
			else
			{
				tnc->imvs->destroy(tnc->imvs);
				tnc->imvs = NULL;
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

