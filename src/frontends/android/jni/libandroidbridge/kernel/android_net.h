/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup kernel_android_net kernel_android_net
 * @{ @ingroup kernel_android
 */

#ifndef KERNEL_ANDROID_NET_H_
#define KERNEL_ANDROID_NET_H_

#include <library.h>
#include <kernel/kernel_net.h>

typedef struct kernel_android_net_t kernel_android_net_t;

/**
 * Implementation of the kernel-net interface.  This currently consists of only
 * noops because a kernel_net_t implementation is required and we can't use
 * kernel_netlink_net_t at the moment.
 */
struct kernel_android_net_t {

	/**
	 * Implements kernel_net_t interface
	 */
	kernel_net_t interface;
};

/**
 * Create a android net interface instance.
 *
 * @return			kernel_android_net_t instance
 */
kernel_android_net_t *kernel_android_net_create();

#endif /** KERNEL_ANDROID_NET_H_ @}*/
