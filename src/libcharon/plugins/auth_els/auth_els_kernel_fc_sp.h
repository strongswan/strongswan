/* Copyright (C) 2019-2020 Marvell */

/**
 * @defgroup auth_els-kernel-ipsec kernel ipsec
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_KERNEL_IPSEC_H_
#define AUTH_ELS_KERNEL_IPSEC_H_

#include <kernel/kernel_ipsec.h>
#include <sa/ike_sa.h>

typedef struct auth_els_kernel_fc_sp_t auth_els_kernel_fc_sp_t;

/**
 * auth_els implementation of the kernel ipsec interface.
 */
struct auth_els_kernel_fc_sp_t {

	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;

};

/**
 * Create a auth_els kernel ipsec interface instance.
 *
 * @return			auth_els_kernel_ipsec_t instance
 */
auth_els_kernel_fc_sp_t *auth_els_kernel_fc_sp_create();

#endif /** AUTH_ELS_KERNEL_IPSEC_H_ @}*/
