/*
 * Copyright (C) 2008 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 2019-2020 Marvell
 * 
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

#include "kernel_fc_sp.h"

#include <daemon.h>

/**
 * See header
 */
bool kernel_fc_sp_register(plugin_t *plugin, plugin_feature_t *feature,
						   bool reg, void *data)
{
	if (reg)
	{
		return charon->kernel->add_fc_sp_interface(charon->kernel,
											(kernel_fc_sp_constructor_t)data);
	}
	else
	{
		return charon->kernel->remove_fc_sp_interface(charon->kernel,
											(kernel_fc_sp_constructor_t)data);
	}
}


