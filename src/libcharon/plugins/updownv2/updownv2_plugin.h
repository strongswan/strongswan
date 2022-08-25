/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2022 Noel Kuntze
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
 * @defgroup updown updown
 * @ingroup cplugins
 *
 * @defgroup updownv2_plugin updownv2_plugin
 * @{ @ingroup updown
 */

#ifndef updownv2_PLUGIN_H_
#define updownv2_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct updownv2_plugin_t updownv2_plugin_t;

/**
 * Updown firewall script invocation plugin, compatible to pluto ones.
 */
struct updownv2_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** updownv2_PLUGIN_H_ @}*/
