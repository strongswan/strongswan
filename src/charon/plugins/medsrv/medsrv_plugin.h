/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 *
 * $Id$
 */

/**
 * @defgroup medsrv medsrv
 * @ingroup cplugins
 *
 * @defgroup medsrv_plugin medsrv_plugin
 * @{ @ingroup medsrv
 */

#ifndef MEDSRV_PLUGIN_H_
#define MEDSRV_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct medsrv_plugin_t medsrv_plugin_t;

/**
 * Mediation server database plugin.
 */
struct medsrv_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a medsrv_plugin instance.
 */
plugin_t *plugin_create();

#endif /** MEDSRV_PLUGIN_H_ @}*/
