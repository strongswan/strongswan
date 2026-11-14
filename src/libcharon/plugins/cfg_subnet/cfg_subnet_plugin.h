/*
 * Copyright (C) 2026 Manuel Montesdeoca
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

/**
 * @defgroup cfg_subnet cfg_subnet
 * @ingroup cplugins
 *
 * @defgroup cfg_subnet_plugin cfg_subnet_plugin
 * @{ @ingroup cfg_subnet
 */

#ifndef CFG_SUBNET_PLUGIN_H_
#define CFG_SUBNET_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct cfg_subnet_plugin_t cfg_subnet_plugin_t;

/**
 * Request INTERNAL_IP4/6_SUBNET attributes via the IKEv2 configuration
 * payload and narrow CHILD_SAs to the subnets received from the server.
 */
struct cfg_subnet_plugin_t {

	/**
	 * Implements plugin_t. interface.
	 */
	plugin_t plugin;
};

#endif /** CFG_SUBNET_PLUGIN_H_ @}*/
