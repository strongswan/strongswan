/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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
 * @defgroup eap_ms_soh eap_ms_soh
 * @ingroup cplugins
 *
 * @defgroup eap_ms_soh_plugin eap_ms_soh_plugin
 * @{ @ingroup eap_ms_soh
 */

#ifndef EAP_MS_SOH_PLUGIN_H_
#define EAP_MS_SOH_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_ms_soh_plugin_t eap_ms_soh_plugin_t;

/**
 * Plugin providing Microsoft specific EAP_MS_SOH (Statement of Health).
 */
struct eap_ms_soh_plugin_t {

	/**
	 * Implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Create a eap_ms_soh_plugin instance.
 */
plugin_t *eap_ms_soh_plugin_create();

#endif /** EAP_MS_SOH_PLUGIN_H_ @}*/
