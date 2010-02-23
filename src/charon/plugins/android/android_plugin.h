/*
 * Copyright (C) 2010 Martin Willi
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
 * @defgroup android android
 * @ingroup cplugins
 *
 * @defgroup android_plugin android_plugin
 * @{ @ingroup android
 */

#ifndef ANDROID_PLUGIN_H_
#define ANDROID_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct android_plugin_t android_plugin_t;

/**
 * Plugin providing functionality specific to the Android platform.
 */
struct android_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** ANDROID_PLUGIN_H_ @}*/
