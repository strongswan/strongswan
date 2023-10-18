/*
 * Copyright (c) 2021 Nanoteq Pty Ltd
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup kernel_vpp kernel_vpp
 * @ingroup cplugins
 *
 * @defgroup kernel_vpp_plugin kernel_vpp_plugin
 * @{ @ingroup kernel_vpp
 */

#ifndef KERNEL_VPP_PLUGIN_H_
#define KERNEL_VPP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct kernel_vpp_plugin_t kernel_vpp_plugin_t;

/**
 * FD.io VPP Interface plugin
 *
 * This plugin implements a kernel interface for strongSwan to communicate with
 * the VPP process.
 */
struct kernel_vpp_plugin_t {

	/**
	 * Implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** KERNEL_VPP_PLUGIN_H_ @}*/
