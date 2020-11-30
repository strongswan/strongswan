/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup socket_vpp socket_vpp
 * @ingroup cplugins
 *
 * @defgroup socket_vpp_plugin socket_vpp_plugin
 * @{ @ingroup socket_vpp
 */

#ifndef SOCKET_VPP_PLUGIN_H_
#define SOCKET_VPP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct socket_vpp_plugin_t socket_vpp_plugin_t;

/**
 * VPP socket implementation plugin.
 */
struct socket_vpp_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** SOCKET_VPP_PLUGIN_H_ @}*/

/*
 * fd.io coding-style-patch-verification: CLANG
 */
