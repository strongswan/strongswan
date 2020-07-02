/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 *
 * Copyright (C) 2008 Tobias Brunner
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
 */
#ifndef KERNEL_VPP_NET_H_
#define KERNEL_VPP_NET_H_

#include <kernel/kernel_net.h>

typedef struct kernel_vpp_net_t kernel_vpp_net_t;

/**
 * Implementation of the kernel network interface using Netlink.
 */
struct kernel_vpp_net_t {

	/**
	 * Implements kernel_net_t interface
	 */
	kernel_net_t interface;

	/* How do we do this w/o access to the vpp net? */
	/* uint32_t get_sw_if_index(kernel_vpp_net_t *this, const char *name); */
};

/**
 * Create a vpp kernel network interface instance.
 *
 * @return          kernel_vpp_net_t instance
 */
kernel_vpp_net_t *kernel_vpp_net_create();

#endif /** KERNEL_VPP_NET_H_ @}*/

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
