#ifndef KERNEL_VPP_PLUGIN_H_
#define KERNEL_VPP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct kernel_vpp_plugin_t kernel_vpp_plugin_t;

/**
 * vpp kernel interface plugin
 */
struct kernel_vpp_plugin_t {

    /**
     * implements plugin interface
     */
    plugin_t plugin;
};

#endif /** KERNEL_VPP_PLUGIN_H_ @}*/
