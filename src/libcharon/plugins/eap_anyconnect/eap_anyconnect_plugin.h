/*
 * Copyright (C) 2020 Stefan Gula
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
 * @defgroup eap_anyconnect eap_anyconnect
 * @ingroup cplugins
 *
 * @defgroup eap_anyconnect_plugin eap_anyconnect_plugin
 * @{ @ingroup eap_anyconnect
 */

#ifndef EAP_ANYCONNECT_PLUGIN_H_
#define EAP_ANYCONNECT_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_anyconnect_plugin_t eap_anyconnect_plugin_t;

/**
 * EAP-ANYCONNECT plugin
 */
struct eap_anyconnect_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** EAP_ANYCONNECT_PLUGIN_H_ @}*/
