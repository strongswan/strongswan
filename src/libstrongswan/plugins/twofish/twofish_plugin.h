/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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
 * @defgroup twofish_p twofish
 * @ingroup plugins
 *
 * @defgroup twofish_plugin twofish_plugin
 * @{ @ingroup twofish_p
 */

#ifndef TWOFISH_PLUGIN_H_
#define TWOFISH_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct twofish_plugin_t twofish_plugin_t;

/**
 * Plugin implementing Twofish based algorithms in software.
 */
struct twofish_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a twofish_plugin instance.
 */
plugin_t *plugin_create();

#endif /** TWOFISH_PLUGIN_H_ @}*/
