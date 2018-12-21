/*
 * Copyright (C) 2009 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
 * Copyright (C) 2018 Sophos, Inc.
 */

/**
 * @defgroup kernel_syscfg kernel_syscfg
 * @ingroup cplugins
 *
 * @defgroup kernel_syscfg_plugin kernel_syscfg_plugin
 * @{ @ingroup kernel_syscfg
 */

#ifndef KERNEL_SYSCFG_PLUGIN_H_
#define KERNEL_SYSCFG_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct kernel_syscfg_plugin_t kernel_syscfg_plugin_t;

/**
 * PF_ROUTE kernel interface plugin
 */
struct kernel_syscfg_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** KERNEL_SYSCFG_PLUGIN_H_ @}*/
