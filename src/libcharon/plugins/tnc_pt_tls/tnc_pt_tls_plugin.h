/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup pt_tls pt_tls
 * @ingroup cplugins
 *
 * @defgroup pt_tls_plugin pt_tls_plugin
 * @{ @ingroup pt_tls
 */

#ifndef PT_TLS_PLUGIN_H_
#define PT_TLS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pt_tls_plugin_t pt_tls_plugin_t;

/**
 * EAP-TNC plugin
 */
struct pt_tls_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** PT_TLS_PLUGIN_H_ @}*/
