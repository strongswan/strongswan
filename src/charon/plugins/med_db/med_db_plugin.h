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
 * @defgroup med_db med_db
 * @ingroup cplugins
 *
 * @defgroup med_db_plugin med_db_plugin
 * @{ @ingroup med_db
 */

#ifndef MED_DB_PLUGIN_H_
#define MED_DB_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct med_db_plugin_t med_db_plugin_t;

/**
 * Mediation server database plugin.
 */
struct med_db_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a med_db_plugin instance.
 */
plugin_t *plugin_create();

#endif /* MED_DB_PLUGIN_H_ @}*/
