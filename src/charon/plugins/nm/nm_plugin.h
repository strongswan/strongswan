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
 * @defgroup nm nm
 * @ingroup cplugins
 *
 * @defgroup nm_plugin nm_plugin
 * @{ @ingroup nm
 */

#ifndef NM_PLUGIN_H_
#define NM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct nm_plugin_t nm_plugin_t;

/**
 * NetworkManager integration plugin.
 */
struct nm_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a nm_plugin instance.
 */
plugin_t *plugin_create();

#endif /* NM_PLUGIN_H_ @}*/
