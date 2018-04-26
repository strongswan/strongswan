/*
 * Copyright (C) 2018 Sophos Group plc
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
 * @defgroup windows_dns windows_dns
 * @ingroup cplugins
 *
 * @defgroup windows_dns_plugin windows_dns_plugin
 * @{ @ingroup windows_dns
 */

#ifndef WINDOWS_DNS_PLUGIN_H_
#define WINDOWS_DNS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct windows_dns_plugin_t windows_dns_plugin_t;

/**
 * Plugin providing an Windows-specific handler for DNS servers.
 */
struct windows_dns_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** WINDOWS_DNS_PLUGIN_H_ @}*/
