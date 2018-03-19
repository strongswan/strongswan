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
};

/**
 * Create a vpp kernel network interface instance.
 *
 * @return          kernel_vpp_net_t instance
 */
kernel_vpp_net_t *kernel_vpp_net_create();

#endif /** KERNEL_VPP_NET_H_ @}*/
