#ifndef KERNEL_VPP_IPSEC_H_
#define KERNEL_VPP_IPSEC_H_

#include <kernel/kernel_ipsec.h>

typedef struct kernel_vpp_ipsec_t kernel_vpp_ipsec_t;

/**
 * Implementation of the kernel ipsec interface using Netlink.
 */
struct kernel_vpp_ipsec_t {

    /**
     * Implements kernel_ipsec_t interface
     */
    kernel_ipsec_t interface;
};

/**
 * Create a vpp kernel ipsec interface instance.
 *
 * @return          kernel_vpp_ipsec_t instance
 */
kernel_vpp_ipsec_t *kernel_vpp_ipsec_create();

#endif /** KERNEL_VPP_IPSEC_H_ @}*/
