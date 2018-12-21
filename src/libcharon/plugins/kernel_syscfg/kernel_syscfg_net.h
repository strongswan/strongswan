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
 * @defgroup kernel_syscfg_net_i kernel_syscfg_net
 * @{ @ingroup kernel_syscfg
 */

#ifndef KERNEL_SYSCFG_NET_H_
#define KERNEL_SYSCFG_NET_H_

#include <kernel/kernel_net.h>

typedef struct kernel_syscfg_net_t kernel_syscfg_net_t;

/**
 * Implementation of the kernel net interface using PF_ROUTE.
 */
struct kernel_syscfg_net_t {

	/**
	 * Implements kernel_net_t interface
	 */
	kernel_net_t interface;
};

/**
 * Create a PF_ROUTE kernel net interface instance.
 *
 * @return			kernel_syscfg_net_t instance
 */
kernel_syscfg_net_t *kernel_syscfg_net_create();

#endif /** KERNEL_SYSCFG_NET_H_ @}*/
