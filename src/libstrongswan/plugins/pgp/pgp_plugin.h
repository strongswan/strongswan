/*
 * Copyright (C) 2009 Martin Willi
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
 */

/**
 * @defgroup pgp_p pgp
 * @ingroup plugins
 *
 * @defgroup pgp_plugin pgp_plugin
 * @{ @ingroup pgp_p
 */

#ifndef PGP_PLUGIN_H_
#define PGP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pgp_plugin_t pgp_plugin_t;

/**
 * Plugin providing PKCS#1 private/public key decoding functions
 */
struct pgp_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a pgp_plugin instance.
 */
plugin_t *plugin_create();

#endif /** PGP_PLUGIN_H_ @}*/
