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
