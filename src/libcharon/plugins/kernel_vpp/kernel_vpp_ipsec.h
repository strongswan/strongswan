/*
 * Copyright (c) 2021 Nanoteq Pty Ltd
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup kernel_vpp_ipsec kernel_vpp_ipsec
 * @{ @ingroup kernel_vpp
 */

#ifndef KERNEL_VPP_IPSEC_H_
#define KERNEL_VPP_IPSEC_H_

#include <kernel/kernel_ipsec.h>

typedef struct kernel_vpp_ipsec_t kernel_vpp_ipsec_t;

/**
 * Implementation of the kernel-ipsec interface using FD.io VPP.
 */
struct kernel_vpp_ipsec_t {

	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;
};

/**
 * Create a FD.io VPP kernel-ipsec interface instance.
 *
 * @return          kernel_vpp_ipsec_t instance
 */
kernel_vpp_ipsec_t *kernel_vpp_ipsec_create();

#endif /** KERNEL_VPP_IPSEC_H_ @}*/
