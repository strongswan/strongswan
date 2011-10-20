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

#define USE_TNC

#include "tnccs.h"

#include <daemon.h>


ENUM(tnccs_type_names, TNCCS_UNKNOWN, TNCCS_2_0,
	"unknown TNCCS",
	"TNCCS 1.1",
	"TNCCS SOH",
	"TNCCS 2.0",
);

/**
 * See header
 */
bool tnccs_method_register(plugin_t *plugin, plugin_feature_t *feature,
						   bool reg, void *data)
{
	if (reg)
	{
		if (feature->type == FEATURE_CUSTOM)
		{
			tnccs_type_t type = TNCCS_UNKNOWN;

			if (streq(feature->arg.custom, "tnccs-2.0"))
			{
				type = TNCCS_2_0;
			}
			else if (streq(feature->arg.custom, "tnccs-1.1"))
			{
				type = TNCCS_1_1;
			}
			else if (streq(feature->arg.custom, "tnccs-dynamic"))
			{
				type = TNCCS_DYNAMIC;
			}
			else
			{
				return FALSE;
			}
			charon->tnccs->add_method(charon->tnccs, type,
									 (tnccs_constructor_t)data);
		}
	}
	else
	{
		charon->tnccs->remove_method(charon->tnccs, (tnccs_constructor_t)data);
	}
	return TRUE;
}
